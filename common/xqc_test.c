#include <stdio.h>

#include "xqc_memory_pool.h"

int main(int argc, char* argv[])
{
    xqc_memory_pool_t *pool = xqc_create_pool(1000);
    void *p1 = xqc_palloc(pool, 10);
    void *p2 = xqc_pnalloc(pool, 20);
    void *p3 = xqc_pcalloc(pool, 30);
    printf("%p %p %p\n", p1, p2, p3);
    xqc_destroy_pool(pool);

    return 0;
}

