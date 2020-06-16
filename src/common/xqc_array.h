#ifndef _XQC_H_ARRAY_INCLUDED_
#define _XQC_H_ARRAY_INCLUDED_

#include <string.h>

#include "src/common/xqc_malloc.h"

/*
 * 动态数组、底层是连续内存
 * */
typedef struct xqc_array_s
{
    void* elts;                 /*首元素指针*/
    unsigned elt_size;          /*每个元素的大小*/
    unsigned size;              /*元素数量*/
    unsigned capacity;          /*元素容量*/
    xqc_allocator_t allocator;  /*内存配置器*/
} xqc_array_t;

/*
 * 创建
 * */
static inline xqc_array_t *xqc_array_create(xqc_allocator_t allocator, size_t elt_capacity, size_t elt_size)
{
    xqc_array_t *a = allocator.malloc(allocator.opaque, sizeof(xqc_array_t));
    if (a == NULL) {
        return NULL;
    }

    a->elts = allocator.malloc(allocator.opaque, elt_capacity * elt_size);
    if (a->elts == NULL) {
        allocator.free(allocator.opaque, a);
        return NULL;
    }
    a->elt_size = elt_size;
    a->size = 0;
    a->capacity = elt_capacity;
    a->allocator = allocator;
    return a;
}

/*
 * 销毁
 * */
static inline void xqc_array_destroy(xqc_array_t *a)
{
    a->allocator.free(a->allocator.opaque, a->elts);
    /*a->elts = NULL;*/

    a->allocator.free(a->allocator.opaque, a);
    /*a = NULL;*/
}

/*
 * 添加n个元素
 * */
static inline void *xqc_array_push_n(xqc_array_t *a, size_t n)
{
    if (a->size + n > a->capacity) {

        size_t new_capacity = (a->capacity >= n ? a->capacity : n) * 2;
        void* p = a->allocator.malloc(a->allocator.opaque, a->elt_size * new_capacity);
        if (p == NULL) {
            return NULL;
        }

        memcpy(p, a->elts, a->elt_size * a->size);

        a->allocator.free(a->allocator.opaque, a->elts);

        a->elts = p;
        a->capacity = new_capacity;
    }

    void* p = (char*)a->elts + a->elt_size * a->size;
    a->size += n;

    return p;
}

/*
 * 添加1个元素
 * */
static inline void *xqc_array_push(xqc_array_t *a)
{
    return xqc_array_push_n(a, 1);
}

#endif /*_XQC_H_ARRAY_INCLUDED_*/
