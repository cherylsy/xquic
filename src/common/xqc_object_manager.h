#ifndef _XQC_H_OBJECT_MANAGER_INCLUDED_
#define _XQC_H_OBJECT_MANAGER_INCLUDED_

#include <stdint.h>
#include <assert.h>

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_list.h"

/*
 * 通用的对象管理器：object manager
 * 使用方法请参考单元测试用例
 * 包含对象池和对象管理两个层次
 * 对象alloc/free采用预分配策略，xqc_object_manager_create(capacity)预设容量，不可扩充（可根据需要调整从而支持扩充）
 * xqc_object_id_t object_id是object manager模块内的对象标识，对user透明，可用于查找对象
 * 每个对象内嵌list结点，用于串联对象，自初始化以后，对象一定串联在used/free list中
 * 对象要么被user代码分配出去（此时位于used list），要么尚未分配（此时位于free list）
 * foreach接口以回调函数参数的形式支持对已分配对象的遍历操作
 * 如果user代码希望使用另外的ID建立起跟Object的映射，有2种思路：
 * 1.仿xqc_object_t结构添加OtherID成员变量 2.在外层维护OtherID到ObjectID的HASH
 * */

/*无符号整型(uint32_t)足够*/
typedef unsigned int xqc_object_id_t;

/*无效对象ID*/
#define XQC_INVALID_OBJECT_ID ((xqc_object_id_t)-1)

/*
 * 用于object manager管理的对象
 * 通过object manager管理的结构体需要参考xqc_object_t定义
 * 前面2个成员变量需要为xqc_object_id_t object_id + xqc_list_head_t list
 * */
typedef struct xqc_object_s
{
    xqc_object_id_t object_id;                  /*对象ID，该ID用于object manager模块*/
    xqc_list_head_t list;                       /*object要么在freelist中，要么在usedlist中*/
    char data[0];                               /*其他数据成员、可变长度*/
} xqc_object_t;

/*
 * 对象管理器，预分配策略，负责对象分配、回收、查找（根据ObjectID）、遍历等
 * */
typedef struct xqc_object_manager_s
{
    char *object_pool;                          /*对象池、预分配*/
    size_t capacity;                            /*对象池容量*/

    size_t object_size;                         /*每个对象的size*/

    xqc_list_head_t free_list;                  /*空闲列表，用于分配*/
    xqc_list_head_t used_list;                  /*使用列表，已分配*/
    size_t used_count;                          /*已分配对象计数*/

    xqc_allocator_t a;                          /*内存配置器*/
} xqc_object_manager_t;

/*
 * 创建
 * */
static inline xqc_object_manager_t *xqc_object_manager_create(size_t object_size, size_t capacity, xqc_allocator_t a)
{
    size_t size = sizeof(xqc_object_manager_t) + (object_size * capacity);
    xqc_object_manager_t *manager = a.malloc(a.opaque, size);
    if (manager == NULL) {
        return NULL;
    }

    manager->object_pool = (char*)(manager + 1);
    manager->capacity = capacity;
    manager->object_size = object_size;

    /*刚开始所有对象都置于freelist*/
    xqc_init_list_head(&manager->free_list);
    for (size_t i = 0; i < capacity; ++i) {
        xqc_object_t* o = (xqc_object_t*)(manager->object_pool + i * object_size);
        o->object_id = i; /*设置ObjectID，且不再变化*/
        xqc_list_add_tail(&o->list, &manager->free_list);
    }

    /*usedlist为空*/
    xqc_init_list_head(&manager->used_list);

    manager->used_count = 0;
    manager->a = a;
    return manager;
}

/*
 * 销毁
 * */
static inline void xqc_object_manager_destroy(xqc_object_manager_t* manager)
{
    xqc_allocator_t *a = &manager->a;
    a->free(a->opaque, manager);
}

/*
 * 查找 O(1)时间复杂度
 * */
static inline xqc_object_t* xqc_object_manager_find(xqc_object_manager_t* manager, xqc_object_id_t id)
{
    if (id >= manager->capacity) {
        return NULL;
    }
    return (xqc_object_t*) (manager->object_pool + id * manager->object_size);
}

/*
 * 分配(申请)对象 O(1)时间复杂度
 * */
static inline xqc_object_t* xqc_object_manager_alloc(xqc_object_manager_t* manager)
{
    if (manager->used_count >= manager->capacity) {
        return NULL;
    }

    assert(!xqc_list_empty(&manager->free_list));

    xqc_list_head_t* node = manager->free_list.next;
    xqc_list_del_init(node); /*从freelist摘除*/

    xqc_list_add_tail(node, &manager->used_list); /*添加到usedlist*/

    ++manager->used_count;

    return xqc_list_entry(node, xqc_object_t, list);
}

/*
 * 释放(归还)对象 O(1)时间复杂度
 * */
static inline int xqc_object_manager_free(xqc_object_manager_t* manager, xqc_object_id_t id)
{
    xqc_object_t* o = xqc_object_manager_find(manager, id);
    if (o == NULL) {
        return -1;
    } 

    assert(!xqc_list_empty(&o->list));

    xqc_list_del_init(&o->list); /*从used list脱链*/
    xqc_list_add(&o->list, &manager->free_list); /*添加到free list*/

    --manager->used_count;
    return 0;
}

/*
 * 重新调整容量
 * */
static inline xqc_object_manager_t* xqc_object_manager_recapacity(xqc_object_manager_t* manager, size_t new_capacity)
{
    if (manager->used_count > new_capacity) {
        return NULL;
    }

    /*创建新的object manager*/
    xqc_object_manager_t* new_manager = xqc_object_manager_create(manager->object_size, new_capacity, manager->a);
    if (new_manager == NULL) {
        return NULL;
    }

    /*从原manager拷贝used list到新manager*/
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &manager->used_list) {
        xqc_object_t *from = xqc_list_entry(pos, xqc_object_t, list);
        xqc_object_t *to = xqc_object_manager_alloc(new_manager);
        memcpy(to->data, from->data, manager->object_size - sizeof(xqc_object_t));
    }

    /*销毁原manager*/
    xqc_object_manager_destroy(manager);

    /*返回新manager*/
    return new_manager;
}

/*
 * 遍历 callback
 * */
static inline void xqc_object_manager_foreach(xqc_object_manager_t* manager, void (*cb)(xqc_object_t*))
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &manager->used_list)
    {
        xqc_object_t *o = xqc_list_entry(pos, xqc_object_t, list);
        cb(o);
    }
}

/*
 * 已分配对象数目
 * */
static inline size_t xqc_object_manager_used_count(xqc_object_manager_t* manager)
{
    return manager->used_count;
}

/*
 * Free对象数目
 * */
static inline size_t xqc_object_manager_free_count(xqc_object_manager_t* manager)
{
    assert(manager->capacity >= manager->used_count);
    return manager->capacity - manager->used_count;
}

#endif /*_XQC_H_OBJECT_MANAGER_INCLUDED_*/
