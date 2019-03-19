#include <CUnit/CUnit.h>

#include "xqc_pq_test.h"

void test_xqc_pq()
{
    xqc_pq_t pq;
    xqc_pq_init(&pq, sizeof(unsigned int), 4, xqc_default_allocator);
    xqc_pq_push(&pq, 4);
    xqc_pq_push(&pq, 5);
    xqc_pq_push(&pq, 1);
    xqc_pq_push(&pq, 3);
    xqc_pq_push(&pq, 2);

    while (!xqc_pq_empty(&pq)) {
        xqc_pq_element_t* e = xqc_pq_top(&pq);
        printf("element key:%u\n", e->key);
        xqc_pq_pop(&pq);
    }

    xqc_pq_destroy(&pq);
}

