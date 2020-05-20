#ifndef _XQC_QUEUE_H_INCLUED_
#define _XQC_QUEUE_H_INCLUED_

#include <stddef.h>

/*
 * 用双向链表实现的队列
 * */

typedef struct xqc_queue_s
{
    struct xqc_queue_s *prev;
    struct xqc_queue_s *next;
} xqc_queue_t;

/*
 * xqc_queue_t初始化
 * */
#define xqc_queue_initialize(q) { &(q), &(q) }

/*
 * 初始化队列
 * */
#define xqc_queue_init(q) \
    do\
    {\
        (q)->prev = q;\
        (q)->next = q;\
    } while (0)

/*
 * 队列判空
 * */
#define xqc_queue_empty(q)\
    ((q) == (q)->prev)

/*
 * 插入队首
 * */
#define xqc_queue_insert_head(h, x)\
    do\
    {\
        (x)->next = (h)->next;\
        (x)->next->prev = x;\
        (x)->prev = h;\
        (h)->next = x;\
    } while (0)

/*
 * 插入队尾
 * */
#define xqc_queue_insert_tail(h, x)\
    do\
    {\
        (x)->prev = (h)->prev;\
        (x)->prev->next = x;\
        (x)->next = h;\
        (h)->prev = x;\
    } while (0)

/*
 * 队首元素
 * */
#define xqc_queue_head(q) (q)->next

/*
 * 队尾元素
 * */
#define xqc_queue_tail(q) (q)->prev

/*
 * 上一个
 * */
#define xqc_queue_prev(q) (q)->prev

/*
 * 下一个
 * */
#define xqc_queue_next(q) (q)->next

/*
 * 脱队
 * */
#define xqc_queue_remove(x)\
    do\
    {\
        (x)->next->prev = (x)->prev;\
        (x)->prev->next = (x)->next;\
        (x)->prev = NULL;\
        (x)->next = NULL;\
    } while (0)

/*
 * 队列数据
 * */
#define xqc_queue_data(q, type, member)\
    ((type*)((char*)(q) - offsetof(type, member)))

/*
 * 遍历
 * */
#define xqc_queue_foreach(pos, q)\
    for (pos = (q)->next; pos != (q); pos = pos->next)

#endif /*_XQC_QUEUE_H_INCLUED_*/
