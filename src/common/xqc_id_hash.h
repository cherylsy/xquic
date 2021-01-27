#ifndef _XQC_INT_HASH_H_INCLUDED_
#define _XQC_INT_HASH_H_INCLUDED_

#include <stdint.h>
#include <math.h>

#include "src/common/xqc_common.h"
#include "src/common/xqc_memory_pool.h"

/* 使用示例
    xqc_id_hash_table_t hash_tab;
    xqc_id_hash_init(&hash_tab, xqc_default_allocator, 100);

    xqc_id_hash_element_t e1 = {1, "hello"};
    xqc_id_hash_add(&hash_tab, e1);

    xqc_id_hash_element_t e2 = {3, "world"};
    xqc_id_hash_add(&hash_tab, e2);

    xqc_id_hash_element_t e3 = {5, "!"};
    xqc_id_hash_add(&hash_tab, e3);

    char* p1 = xqc_id_hash_find(&hash_tab, 3);
    if (p1) {
        printf("found hash 3: %s\n", p1);
    } else {
        printf("not found hash 3\n");
    }

    void* p2 = xqc_id_hash_find(&hash_tab, 4);
    if (p2) {
        printf("found hash 4: %s\n", p2);
    } else {
        printf("not found hash 4\n");
    }

    int ret = xqc_id_hash_delete(&hash_tab, 3);
    printf("delete 3 return %d\n", ret);

    p1 = xqc_id_hash_find(&hash_tab, 3);
    if (p1) {
        printf("found hash 3: %s\n", p1);
    } else {
        printf("not found hash 3\n");
    }

    xqc_id_hash_release(&hash_tab);
 * */

/*
 * 哈希表元素
 * */
typedef struct xqc_id_hash_element_s
{
    uint64_t hash; /*hash，用于对桶数取模*/
    void *value; /*关联的元素数据*/
} xqc_id_hash_element_t;

/*
 * hash冲突链节点
 * */
typedef struct xqc_id_hash_node_s
{
    struct xqc_id_hash_node_s *next; /*冲突链*/
    xqc_id_hash_element_t element; /*元素*/
} xqc_id_hash_node_t;

/*
 * hash表
 * */
typedef struct xqc_id_hash_table_s
{
    xqc_id_hash_node_t **list; /*桶列表*/
    size_t count; /*桶的数目*/
    size_t mask;
    xqc_allocator_t allocator; /*内存配置器*/
} xqc_id_hash_table_t;


/**
 *  make n to 2 pow 
 * */
static inline int xqc_pow2(unsigned int n) {
    int clz , power = sizeof(n);
    if (__builtin_popcount(n) <= 1) {
        return n ;
    }
    clz     = __builtin_clz(n);
    power   = (power << 3) - clz ;
    return pow(2 , power);
}

/*
 * 哈希表初始化
 * */
static inline int xqc_id_hash_init(xqc_id_hash_table_t* hash_tab,  xqc_allocator_t allocator, size_t bucket_num)
{
    hash_tab->allocator = allocator;
    bucket_num = xqc_pow2(bucket_num);
    hash_tab->list = allocator.malloc(allocator.opaque, sizeof(xqc_id_hash_node_t*) * bucket_num);
    if (hash_tab->list == NULL) {
        return XQC_ERROR;
    }
    memset(hash_tab->list, 0, sizeof(xqc_id_hash_node_t*) * bucket_num);
    hash_tab->count = bucket_num;
    hash_tab->mask  = bucket_num - 1 ;
    return XQC_OK;
}

/*
 * 哈希表释放
 * */
static inline void xqc_id_hash_release(xqc_id_hash_table_t* hash_tab)
{
    xqc_allocator_t* a = &hash_tab->allocator;
    for (size_t i = 0; i < hash_tab->count; ++i) {
        xqc_id_hash_node_t* node = hash_tab->list[i];
        while (node) {
            xqc_id_hash_node_t* p = node;
            if (node->next == node) {
                break;
            }
            node = node->next;
            a->free(a->opaque, p);
        }
    }
    a->free(a->opaque, hash_tab->list);
}

/*
 * 查找
 * */
static inline void* xqc_id_hash_find(xqc_id_hash_table_t* hash_tab, uint64_t hash)
{
    uint64_t index = hash & hash_tab->mask;
    xqc_id_hash_node_t* node = hash_tab->list[index];
    while (node) {
        if (node->element.hash == hash) {
            return node->element.value;
        }
        if (node->next == node) {
            return NULL;
        }
        node = node->next;
    }
    return NULL;
}

/*
 * 添加元素
 * */
static inline int xqc_id_hash_add(xqc_id_hash_table_t* hash_tab, xqc_id_hash_element_t e)
{
    if (xqc_id_hash_find(hash_tab, e.hash)) {
        return XQC_ERROR;
    }

    uint64_t index = e.hash & hash_tab->mask;
    xqc_allocator_t *a = &hash_tab->allocator;
    xqc_id_hash_node_t* node = a->malloc(a->opaque, sizeof(xqc_id_hash_node_t));
    if (node == NULL) {
        return XQC_ERROR;
    }

    node->element = e;
    node->next = hash_tab->list[index];
    hash_tab->list[index] = node;

    return XQC_OK;
}

/*
 * 删除元素
 * */
static inline int xqc_id_hash_delete(xqc_id_hash_table_t* hash_tab, uint64_t hash)
{
    uint64_t index = hash & hash_tab->mask;
    xqc_allocator_t *a = &hash_tab->allocator;
    xqc_id_hash_node_t** pp = &hash_tab->list[index];
    xqc_id_hash_node_t* node = hash_tab->list[index];
    while (node) {
        if (node->element.hash == hash) {
            *pp = node->next; /*从冲突链删除*/
            a->free(a->opaque, node);
            return XQC_OK;
        }
#define XQC_ID_HASH_LOOP -9
        if (node->next == node) {
            return XQC_ID_HASH_LOOP;
        }
        pp = &node->next;
        node = node->next;
    }

    return XQC_ERROR;
}

#endif
