#include <CUnit/CUnit.h>

#include "xqc_common_test.h"

typedef struct person_s
{
    int age;
    char name[20];
    xqc_queue_t queue;
} person_t;

void test_xqc_common()
{
    /*test queue*/
    xqc_queue_t q;
    xqc_queue_init(&q);
    person_t p1 = { 1, "a1", xqc_queue_initialize(p1.queue) };
    person_t p2 = { 2, "z2", xqc_queue_initialize(p2.queue) };
    person_t p3 = { 3, "s3", xqc_queue_initialize(p3.queue) };
    person_t p4 = { 4, "f4", xqc_queue_initialize(p4.queue) };

    xqc_queue_insert_head(&q, &p1.queue);
    xqc_queue_insert_tail(&q, &p2.queue);
    xqc_queue_insert_head(&q, &p3.queue);
    xqc_queue_insert_tail(&q, &p4.queue);
    xqc_queue_remove(&p3.queue);

    int a[4] = {1,2,4};
    int i = 0;

    xqc_queue_t* pos;
    xqc_queue_foreach(pos, &q)
    {
        person_t* p = xqc_queue_data(pos, person_t, queue);
        CU_ASSERT(p->age == a[i]);
        ++i;
    }

    /*test hash functions*/
    xqc_md5_t ctx;
    xqc_md5_init(&ctx);
    unsigned char buf[] = "hello,world";
    xqc_md5_update(&ctx, buf, 11);

    unsigned char final[16] = {};
    xqc_md5_final(final, &ctx);

    for (int i = 0; i < 16; ++i) {
        printf("%c\n", final[i]);
    }

    uint32_t hash_value = ngx_murmur_hash2(buf, 11);
    printf("hash value:%u\n", hash_value);
}
