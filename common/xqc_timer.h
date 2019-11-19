#ifndef _XQC_H_TIMER_INCLUED_
#define _XQC_H_TIMER_INCLUED_

#include <stdint.h>
#include "xqc_time.h"
#include "xqc_list.h"

/*
 * 基于时间轮的定时器实现
 * 精度设计为1毫秒，当然这取决于调用滴答函数的精度
 * 初始化：xqc_timer_manager_init()
 * 滴答：xqc_timer_manager_tick()
 * 添加定时器：xqc_timer_manager_add()，定时器响铃之后如果需要重设定时可以在callback函数中在加上去（支持repeat模式）
 * */

/*
 * 定时器回调函数
 * */
typedef void (*xqc_timer_function)(unsigned long);

/*
 * 定时器结构
 * */
typedef struct xqc_timer_s
{
    xqc_list_head_t list;           /*链表串联*/
    unsigned long expires;          /*过期时间*/
    unsigned long data;             /*传递给callback的数据*/
    xqc_timer_function function;    /*callback*/
} xqc_timer_t;

/*
 * 初始化定时器
 * */
static inline void xqc_timer_init(xqc_timer_t *timer)
{
    timer->list.prev = NULL;
    timer->list.next = NULL;
    timer->expires = 0;
    timer->data = 0;
    timer->function = NULL;
}

#define XQC_VEC1_BITS (14)
#define XQC_VEC2_BITS (8)

#define XQC_VEC1_SIZE (1 << (XQC_VEC1_BITS))
#define XQC_VEC2_SIZE (1 << (XQC_VEC2_BITS))

#define XQC_VEC1_MASK ((XQC_VEC1_SIZE) - 1)
#define XQC_VEC2_MASK ((XQC_VEC2_SIZE) - 1)

/*
 * 定时器管理器、全局唯一
 * */
typedef struct xqc_timer_manager_s
{
    uint64_t timestamp;                     /*上一次tick时间戳*/

    unsigned int index1;                    /*vec1索引*/
    xqc_list_head_t vec1[XQC_VEC1_SIZE];    /*紧迫定时器链表数组*/

    unsigned int index2;                    /*vec2索引*/
    xqc_list_head_t vec2[XQC_VEC2_SIZE];    /*松散定时器链表数组*/
} xqc_timer_manager_t;

static inline uint64_t xqc_gettimeofday()
{
    /*获取毫秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return  ul;
}

/*
 * 定时器管理器初始化
 * */
static inline void xqc_timer_manager_init(xqc_timer_manager_t* manager)
{
    manager->timestamp = xqc_gettimeofday();

    manager->index1 = manager->timestamp & XQC_VEC1_MASK;
    for (int i = 0; i < XQC_VEC1_SIZE; ++i) {
        xqc_init_list_head(&manager->vec1[i]);
    }

    manager->index2 = (manager->timestamp >> XQC_VEC1_BITS) & XQC_VEC2_MASK;
    for (int i = 0; i < XQC_VEC2_SIZE; ++i) {
        xqc_init_list_head(&manager->vec2[i]);
    }
}

static inline int xqc_timer_manager_internal_add(xqc_timer_manager_t* manager, xqc_timer_t *timer)
{
    xqc_list_head_t *vec = NULL;

    unsigned long expires= timer->expires;
    unsigned long idx = expires - manager->timestamp;

    if (idx < XQC_VEC1_SIZE) {
        int i = expires & XQC_VEC1_MASK;
        vec = manager->vec1 + i;
    } else if (idx < (1 << (XQC_VEC1_BITS + XQC_VEC2_BITS))) {
        int i = (expires >> XQC_VEC1_BITS) & XQC_VEC2_MASK;
        vec = manager->vec2 + i;
    } else {
        printf("xqc timer add error:%lu\n", idx);
        return -1;
    }

    xqc_list_add(&timer->list, vec->prev);
    return 0;
}

/*
 * 添加定时器 timeout毫秒后响铃
 * */
static inline int xqc_timer_manager_add(xqc_timer_manager_t* manager, xqc_timer_t *timer, unsigned long timeout)
{
    if (timer->function == NULL) {
        printf("timer function null\n");
        return 1;
    }
    unsigned long now = xqc_gettimeofday();
    timer->expires = now + timeout;
    int ret = xqc_timer_manager_internal_add(manager, timer);
#if 0
    if (ret == 0) {
        printf("add timer OK, timeout=%lu, expires=%lu\n", timeout, timer->expires);
    }
#endif
    return ret;
}

static inline void xqc_timer_manager_cascade(xqc_timer_manager_t* manager)
{
    xqc_list_head_t *head, *curr, *next;

    head = manager->vec2 + manager->index2;
    curr = head->next;
    while (curr != head) {
        xqc_timer_t *tmp = xqc_list_entry(curr, xqc_timer_t, list);
        next = curr->next;

        xqc_list_del(curr); // not needed
        curr->next = curr->prev = NULL;

        xqc_timer_manager_internal_add(manager, tmp);

        curr = next;
    }

    head->prev = head->next = head;
    manager->index2 = (manager->index2 + 1) & XQC_VEC2_MASK;
}

/*
 * 定时管理器滴答 驱动
 * */
static inline void xqc_timer_manager_tick(xqc_timer_manager_t* manager)
{
    unsigned long now = xqc_gettimeofday();
    while (now >= manager->timestamp) {
        if (manager->index1 == 0) {
            xqc_timer_manager_cascade(manager);
        }

        xqc_list_head_t *head = manager->vec1 + manager->index1;
        xqc_list_head_t *curr = head->next;

        while (curr != head) {
            xqc_timer_t *timer = xqc_list_entry(curr, xqc_timer_t, list);
            xqc_timer_function fn = timer->function;
            unsigned long data= timer->data;

            xqc_list_del(&timer->list);
            timer->list.prev = timer->list.next = NULL;

            fn(data);

            head = manager->vec1 + manager->index1;
            curr = head->next;
        }

        manager->timestamp++;
        manager->index1 = (manager->index1 + 1) & XQC_VEC1_MASK;
    }
}

#endif /*_XQC_H_TIMER_INCLUED_*/

