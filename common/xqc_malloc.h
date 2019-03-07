#pragma once

#include <stdlib.h>

/*
 * 收口动态内存分配和回收、以便日后可以做一些控制和统计
 * 暂时只做调用转交
 * */

static inline void* xqc_malloc(size_t size)
{
    return malloc(size);
}

static inline void* xqc_calloc(size_t count, size_t size)
{
    return calloc(count, size);
}

static inline void* xqc_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

static inline void xqc_free(void* ptr)
{
    free(ptr);
}

