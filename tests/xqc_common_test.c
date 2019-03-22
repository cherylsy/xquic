#include <CUnit/CUnit.h>

#include "xqc_common_test.h"
#include "../common/xqc_object_manager.h"

typedef struct person_s
{
    int age;
    char name[20];
    xqc_queue_t queue;
} person_t;

typedef struct xqc_item_s
{
    xqc_object_id_t object_id;
    xqc_list_head_t list;
    int data;
} xqc_item_t;

static inline void test_object_manager_cb(xqc_object_t *o)
{
    /*xqc_item_t* item = (xqc_item_t*)o;
    printf("id:%u, data:%d\n", item->object_id, item->data);*/
}

int test_object_manager()
{
    xqc_object_manager_t *manager = xqc_object_manager_create(sizeof(xqc_item_t), 4, xqc_default_allocator);
    if (manager == NULL) {
        return 1;
    }

    xqc_item_t *item1 = (xqc_item_t*)xqc_object_manager_alloc(manager); 
    if (item1) {
        item1->data = 1;
    }

    xqc_item_t *item2 = (xqc_item_t*)xqc_object_manager_alloc(manager);
    if (item2) {
        item2->data = 2;
        xqc_object_manager_free(manager, item2->object_id);
    }

    xqc_item_t *item3 = (xqc_item_t*)xqc_object_manager_alloc(manager);
    if (item3) {
        item3->data = 3;
    }

    xqc_object_manager_foreach(manager, test_object_manager_cb);

    CU_ASSERT(xqc_object_manager_used_count(manager) == 2);
    CU_ASSERT(xqc_object_manager_free_count(manager) == 2);

    xqc_object_manager_destroy(manager);

    return 0;
}


void xqc_test_common()
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

    uint32_t hash_value = ngx_murmur_hash2(buf, 11);
    
    test_object_manager();
}
