#include <stdio.h>

#include "xqc_memory_pool.h"
#include "xqc_id_hash.h"
#include "xqc_str_hash.h"

int test_memory_pool(int argc, char* argv[]);
int test_hash(int argc, char* argv[]);

int main(int argc, char* argv[])
{
#if 0
    test_memory_pool(argc, argv);
#endif

#if 1
    test_hash(argc, argv);
#endif


    return 0;
}

int test_memory_pool(int argc, char* argv[])
{
    xqc_memory_pool_t *pool = xqc_create_pool(1000);
    void *p1 = xqc_palloc(pool, 10);
    void *p2 = xqc_pnalloc(pool, 20);
    void *p3 = xqc_pcalloc(pool, 30);
    printf("%p %p %p\n", p1, p2, p3);
    xqc_destroy_pool(pool);
    return 0;
}

int test_hash(int argc, char* argv[])
{
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
    return 0;
}
