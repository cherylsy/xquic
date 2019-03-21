#ifndef _NGX_H_PRIORITY_Q_INCLUDED_
#define _NGX_H_PRIORITY_Q_INCLUDED_

#include <string.h>
#include <stdint.h>

#include "xqc_malloc.h"

/*
 * 基于二叉堆实现的优先级队列
 * key代表优先权，默认是按从大到小出队，对应xqc_pq_default_cmp；如果要按从小到大出队，传递xqc_pq_revert_cmp
 * 可以通过传入xqc_pq_compare_ptr去改变规则
 * 支持自动扩容，元素大小至少sizeof(xqc_pq_key_t) 8字节
 * 接口：
 * 初始化：xqc_pq_init(), xqc_pq_init_default(capacity=xqc_pq_default_capacity)
 * 压入：xqc_pq_push()
 * 弹出：xqc_pq_pop()
 * 返回顶部元素：xqc_pq_top()
 * 判空：xqc_pq_empty()
 * */

typedef uint64_t xqc_pq_key_t;

typedef struct xqc_priority_queue_element_s
{
    xqc_pq_key_t key;       /*键*/
    char data[0];
} xqc_pq_element_t;

/*
 * element比较函数
 * */
typedef int (*xqc_pq_compare_ptr)(xqc_pq_key_t a, xqc_pq_key_t b);

/*
 * element默认比较函数 a的优先级小于b的优先级
 * 从大到小出队
 * */
static inline int xqc_pq_default_cmp(xqc_pq_key_t a, xqc_pq_key_t b)
{
    return (a < b) ? 1 : 0;
}

/*
 * element反向比较函数 b < a
 * 从小到大出队
 * */
static inline int xqc_pq_revert_cmp(xqc_pq_key_t a, xqc_pq_key_t b)
{
    return (b < a) ? 1 : 0;
}

typedef struct xqc_priority_queue_s
{
    char* elements;         /*元素列表*/
    size_t element_size;    /*元素对象的内存大小*/
    size_t count;           /*元素数量*/
    size_t capacity;        /*容量*/
    xqc_allocator_t a;      /*内存配置器*/
    xqc_pq_compare_ptr cmp; /*比较器*/
} xqc_pq_t;

#define xqc_pq_element(pq, index) ((xqc_pq_element_t*)&(pq)->elements[(index) * (pq)->element_size])
#define xqc_pq_element_copy(pq, dst, src) memcpy(xqc_pq_element((pq), (dst)), xqc_pq_element((pq), (src)), (pq)->element_size)
#define xqc_pq_default_capacity 16

static inline int xqc_pq_init(xqc_pq_t *pq, size_t element_size, size_t capacity, xqc_allocator_t a, xqc_pq_compare_ptr cmp)
{
    if (element_size < sizeof(xqc_pq_element_t) || capacity == 0) {
        return -1;
    }

   pq->elements = a.malloc(a.opaque, element_size * capacity);
   if (pq->elements == NULL) {
       return -2;
   }

   pq->element_size = element_size;
   pq->count = 0;
   pq->capacity = capacity;
   pq->a = a;
   pq->cmp = cmp;

   return 0;
}

static inline int xqc_pq_init_default(xqc_pq_t *pq, size_t element_size, xqc_allocator_t a, xqc_pq_compare_ptr cmp)
{
    return xqc_pq_init(pq, element_size, xqc_pq_default_capacity, a, cmp);
}

static inline void xqc_pq_destroy(xqc_pq_t *pq)
{
    pq->a.free(pq->a.opaque, pq->elements);
    pq->elements = NULL;
    pq->element_size = 0;
    pq->count = 0;
    pq->capacity = 0;
}

static inline void xqc_pq_element_swap(xqc_pq_t *pq, size_t i, size_t j)
{
    char buf[pq->element_size];
    memcpy(buf, xqc_pq_element(pq, j), pq->element_size);
    memcpy(xqc_pq_element(pq, j), xqc_pq_element(pq, i), pq->element_size);
    memcpy(xqc_pq_element(pq, i), buf, pq->element_size);
}

static inline xqc_pq_element_t* xqc_pq_push(xqc_pq_t *pq, xqc_pq_key_t key)
{
    if (pq->count == pq->capacity) {
        /*扩容*/
        size_t capacity = pq->capacity * 2;
        size_t size = capacity * pq->element_size;
        void* buf = pq->a.malloc(pq->a.opaque, size);
        if (buf == NULL) {
            return NULL;
        }
        memcpy(buf, pq->elements, pq->capacity * pq->element_size);
        pq->a.free(pq->a.opaque, pq->elements);
        pq->elements = buf;
        pq->capacity = capacity;
    }

    xqc_pq_element_t* p = xqc_pq_element(pq, pq->count);
    p->key = key;

    size_t i = pq->count++;
    while (i != 0) {
        int j = (i - 1) / 2; /*父节点*/
        if (!pq->cmp(xqc_pq_element(pq, j)->key, xqc_pq_element(pq, i)->key))
            break;

        /*swap*/
        xqc_pq_element_swap(pq, i, j);

        /*父节点变为待调整元素*/
        i = j;
    }

    return xqc_pq_element(pq, i);
}

static inline xqc_pq_element_t* xqc_pq_top(xqc_pq_t *pq)
{
    if (pq->count == 0) {
        return NULL;
    }
    return xqc_pq_element(pq, 0);
}

static inline int xqc_pq_empty(xqc_pq_t *pq)
{
    return pq->count == 0 ? 1 : 0;
}

static inline void xqc_pq_pop(xqc_pq_t *pq)
{
    if (pq->count == 0 || --pq->count == 0) {
        return;
    }

    xqc_pq_element_copy(pq, 0, pq->count);

    int i = 0, j = 2 * i + 1;
    while (j <= pq->count - 1) {
        if (j < pq->count - 1 && pq->cmp(xqc_pq_element(pq, j)->key, xqc_pq_element(pq, j+1)->key)) {
            ++j;
        }

        if (!pq->cmp(xqc_pq_element(pq, i)->key, xqc_pq_element(pq, j)->key)) {
            break;
        }

        xqc_pq_element_swap(pq, i, j);

        i = j;
        j = 2 * i + 1;
    }
}

#undef xqc_pq_element
#undef xqc_pq_element_copy

#endif /*_NGX_H_PRIORITY_Q_INCLUDED_*/
