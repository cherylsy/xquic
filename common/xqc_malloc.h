#ifndef _XQC_MALLOC_H_INCLUDED_
#define _XQC_MALLOC_H_INCLUDED_

#include <stdlib.h>
#include <stdio.h>

/*
 * 收口动态内存分配和回收、以便日后可以做一些控制和统计
 * 暂时只做调用转交
 * */
#ifdef PRINT_MALLOC
#define xqc_malloc(size) ({\
    void *p = malloc((size));\
    printf("PRINT_MALLOC %p %zu %s:%d\n", p, (size_t)(size), __FILE__, __LINE__);\
    (p);\
    })
#else
static inline void* xqc_malloc(size_t size)
{
    return malloc(size);
}
#endif

#ifdef PRINT_MALLOC
#define xqc_calloc(count, size) ({\
    void *p = calloc(count, size);\
    printf("PRINT_MALLOC %p %zu %s:%d\n", p, size, __FILE__, __LINE__);\
    (p);\
    })
#else
static inline void* xqc_calloc(size_t count, size_t size)
{
    return calloc(count, size);
}
#endif

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

