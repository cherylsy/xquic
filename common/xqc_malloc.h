#ifndef _XQC_MALLOC_H_INCLUDED_
#define _XQC_MALLOC_H_INCLUDED_

#include <stdlib.h>
#include <stdio.h>

/*
 * 收口动态内存分配和回收、以便日后可以做一些控制和统计
 * 暂时只做调用转交
 * */

static inline void* xqc_malloc(size_t size)
{
#ifdef PRINT_MALLOC
    void *p = malloc(size);
    printf("PRINT_MALLOC %p %zu\n", p, size);
    return p;
#endif
    return malloc(size);
}

static inline void* xqc_calloc(size_t count, size_t size)
{
#ifdef PRINT_MALLOC
    void *p = calloc(count, size);
    printf("PRINT_MALLOC %p %zu\n", p, size);
    return p;
#endif
    return calloc(count, size);
}

static inline void* xqc_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

static inline void xqc_free(void* ptr)
{
#ifdef PRINT_MALLOC
    printf("PRINT_FREE %p\n", ptr);
    free(ptr);
    return;
#endif
    free(ptr);
}

/*
 * 内存配置器接口
 * */
typedef void* (*xqc_malloc_wrap_t)(void* opaque, size_t size);
typedef void (*xqc_free_wrap_t)(void* opaque, void* ptr);

typedef struct xqc_allocator_s
{
    xqc_malloc_wrap_t malloc;
    xqc_free_wrap_t free;
    void* opaque;
} xqc_allocator_t;

static inline void* xqc_malloc_wrap_default(void* opaque, size_t size)
{
    (void)opaque;
    return xqc_malloc(size);
}

static inline void xqc_free_wrap_default(void* opaque, void* ptr)
{
    (void)opaque;
    return xqc_free(ptr);
}

static xqc_allocator_t xqc_default_allocator = {&xqc_malloc_wrap_default, &xqc_free_wrap_default, NULL};

#endif /*_XQC_MALLOC_H_INCLUDED_*/

