#ifndef _XQC_H_FIFO_INCLUDED_
#define _XQC_H_FIFO_INCLUDED_

#include <stdint.h>

#include "xqc_memory_pool.h"
#include "xqc_common.h"

/*
 * 先进先出队列
 * 其中的元素可以是任意类型，包括int、char、void*以及自定义结构体
 * 需要关注的接口
 * xqc_fifo_init, xqc_fifo_release
 * xqc_fifo_length, xqc_fifo_full, xqc_fifo_empty
 * xqc_fifo_push, xqc_fifo_top, xqc_fifo_pop
 * xqc_fifo_push_typeX, xqc_fifo_top_typeX 封装各种类型，方便使用
 * */

/*
 * FIFO队列结构体
 * */
typedef struct {
    char* buf;                  /*缓冲区*/
    unsigned int in, out;       /*进和出的cursor*/
    unsigned int element_size;  /*元素大小*/
    unsigned int capacity;      /*元素容量*/
    xqc_allocator_t allocator;  /*内存配置器*/
} xqc_fifo_t; 

/*
 * 2次方向上圆整(内部实现)
 * */
static inline size_t
xqc_fifo_roundup(size_t i)
{
    unsigned int n = 2;
    while (n < i) n *= 2;
    return n;
}

/*
 * 初始化
 * */
static inline int
xqc_fifo_init(xqc_fifo_t* fifo, xqc_allocator_t allocator, size_t element_size, size_t capacity)
{
    if (capacity & (capacity - 1)) {
        capacity = xqc_fifo_roundup(capacity);
    }

    fifo->allocator = allocator;
    fifo->buf = allocator.malloc(allocator.opaque, element_size * capacity);
    if (fifo->buf == NULL) {
        return XQC_ERROR;
    }

    fifo->in = 0;
    fifo->out = 0;
    fifo->element_size = element_size;
    fifo->capacity = capacity;

    return XQC_OK;
}

/*
 * 释放
 * */
static inline void
xqc_fifo_release(xqc_fifo_t* fifo)
{
    xqc_allocator_t *a = &fifo->allocator;
    a->free(a->opaque, fifo->buf);
    fifo->buf = NULL;
}

/*
 * 求FIFO元素数量
 * */
static inline size_t
xqc_fifo_length(const xqc_fifo_t* fifo)
{
    return fifo->in - fifo->out;
}

/*
 * 判满
 * */
static inline int
xqc_fifo_full(const xqc_fifo_t* fifo)
{
    return xqc_fifo_length(fifo) >= fifo->capacity ? XQC_TRUE : XQC_FALSE;
}

/*
 * 判空
 * */
static inline int
xqc_fifo_empty(const xqc_fifo_t* fifo)
{
    return xqc_fifo_length(fifo) == 0 ? XQC_TRUE : XQC_FALSE;
}

/*
 * push通用实现
 * */
static inline int
xqc_fifo_push(xqc_fifo_t* fifo, void* buf, size_t size)
{
    if (fifo->element_size != size) {
        return XQC_ERROR;
    }

    if (xqc_fifo_full(fifo)) {
        return XQC_ERROR;
    }

    size_t index = fifo->in++ % fifo->capacity * fifo->element_size;
    memcpy(fifo->buf + index, buf, size);

    return XQC_OK;
}

/*
 * pop 返回OK或者ERROR
 * */
static inline int
xqc_fifo_pop(xqc_fifo_t* fifo)
{
    if (xqc_fifo_empty(fifo) == XQC_TRUE) {
        return XQC_ERROR;
    }

    if (++fifo->out == fifo->in) {
        fifo->in = fifo->out = 0;
    }

    return XQC_OK;
}

/*
 * FIFO首元素
 * */
static inline void*
xqc_fifo_top(xqc_fifo_t* fifo)
{
    if (xqc_fifo_empty(fifo) == XQC_TRUE) {
        return NULL;
    }

    size_t index = fifo->out % fifo->capacity * fifo->element_size;
    return fifo->buf + index;
}

/*
 * 根据类型封装的xqc_fifo_top_xx接口列表
 * */
static inline void*
xqc_fifo_top_ptr(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(void*));
    return *(void**)xqc_fifo_top(fifo);
}

static inline int
xqc_fifo_top_int(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(int));
    return *(int*)xqc_fifo_top(fifo);
}

static inline unsigned int
xqc_fifo_top_uint(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(unsigned int));
    return *(unsigned int*)xqc_fifo_top(fifo);
}

static inline long
xqc_fifo_top_long(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(long));
    return *(long*)xqc_fifo_top(fifo);
}

static inline unsigned long
xqc_fifo_top_ulong(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(unsigned long));
    return *(unsigned long*)xqc_fifo_top(fifo);
}

static inline int8_t
xqc_fifo_top_int8(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(int8_t));
    return *(int8_t*)xqc_fifo_top(fifo);
}

static inline uint8_t
xqc_fifo_top_uint8(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(uint8_t));
    return *(uint8_t*)xqc_fifo_top(fifo);
}

static inline int16_t
xqc_fifo_top_int16(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(int16_t));
    return *(int16_t*)xqc_fifo_top(fifo);
}

static inline uint16_t
xqc_fifo_top_uint16(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(uint16_t));
    return *(uint16_t*)xqc_fifo_top(fifo);
}

static inline int32_t
xqc_fifo_top_int32(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(int32_t));
    return *(int32_t*)xqc_fifo_top(fifo);
}

static inline uint32_t
xqc_fifo_top_uint32(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(uint32_t));
    return *(uint32_t*)xqc_fifo_top(fifo);
}

static inline int64_t
xqc_fifo_top_int64(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(int64_t));
    return *(int64_t*)xqc_fifo_top(fifo);
}

static inline uint64_t
xqc_fifo_top_uint64(xqc_fifo_t* fifo)
{
    assert(fifo->element_size == sizeof(uint64_t));
    return *(uint64_t*)xqc_fifo_top(fifo);
}

/*
 * 根据类型封装的xqc_fifo_push_xx接口列表
 * */
static inline int
xqc_fifo_push_ptr(xqc_fifo_t* fifo, void* ptr)
{
    return xqc_fifo_push(fifo, &ptr, sizeof(ptr));
}

static inline int
xqc_fifo_push_int(xqc_fifo_t* fifo, int i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint(xqc_fifo_t* fifo, unsigned int i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_long(xqc_fifo_t* fifo, long i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_ulong(xqc_fifo_t* fifo, unsigned long i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int8(xqc_fifo_t* fifo, int8_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint8(xqc_fifo_t* fifo, uint8_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int16(xqc_fifo_t* fifo, int16_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint16(xqc_fifo_t* fifo, uint16_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int32(xqc_fifo_t* fifo, int32_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint32(xqc_fifo_t* fifo, uint32_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int64(xqc_fifo_t* fifo, int64_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint64(xqc_fifo_t* fifo, uint64_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

#endif /*_XQC_H_FIFO_INCLUDED_*/

