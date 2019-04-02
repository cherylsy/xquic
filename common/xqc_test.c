#include <stdio.h>

#include "xqc_memory_pool.h"
#include "xqc_id_hash.h"
#include "xqc_cid_hash.h"
#include "xqc_str_hash.h"
#include "xqc_log.h"
#include "xqc_list.h"
#include "xqc_array.h"
#include "xqc_priority_q.h"
#include "xqc_queue.h"
#include "xqc_hash.h"
#include "xqc_object_manager.h"
#include "xqc_rbtree.h"

int test_memory_pool(int argc, char* argv[]);
int test_hash_table(int argc, char* argv[]);
int test_log(int argc, char* argv[]);
int test_list(int argc, char* argv[]);
int test_array(int argc, char* argv[]);
int test_pq(int argc, char* argv[]);
int test_queue(int argc, char* argv[]);
int test_hash(int argc, char* argv[]);
int test_object_manager(int argc, char* argv[]);
int test_rbtree(int argc, char* argv[]);

int main(int argc, char* argv[])
{
#if 0
    test_memory_pool(argc, argv);
#endif

#if 1
    test_hash_table(argc, argv);
#endif

#if 0
    test_log(argc, argv);
#endif

#if 0
    test_list(argc, argv);
#endif

#if 0
    test_array(argc, argv);
#endif

#if 0
    test_pq(argc, argv);
#endif

#if 0
    test_queue(argc, argv);
#endif

#if 0
    test_hash(argc, argv);
#endif

#if 0
    test_object_manager(argc, argv);
#endif

#if 0
    test_rbtree(argc, argv);
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

int test_hash_table(int argc, char* argv[])
{
#if 1
    xqc_cid_hash_table_t hash_tab;
    xqc_cid_hash_init(&hash_tab, xqc_default_allocator, 100);

    unsigned char *cid1 = "12345"; char* p1 = "hello";
    xqc_cid_hash_add(&hash_tab, cid1, 5, p1);

    unsigned char *cid2 = "87654321"; char* p2 = "world";
    xqc_cid_hash_add(&hash_tab, cid2, 8, p2);

    unsigned char *cid3 = "1122"; char* p3 = "wang";
    xqc_cid_hash_add(&hash_tab, cid3, 4, p3);

    char* p = xqc_cid_hash_find(&hash_tab, cid2, 8);
    if (p) {
        printf("found %s\n", p);
    } else {
        printf("not found\n");
    }

    xqc_cid_hash_delete(&hash_tab, cid2, 8);
    printf("after deleted\n");

    p = xqc_cid_hash_find(&hash_tab, cid2, 8);
    if (p) {
        printf("found %s\n", p);
    } else {
        printf("not found\n");
    }
#else
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
        printf("found hash 4: %s\n", (char*)p2);
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
#endif
    return 0;
}

int test_log(int argc, char* argv[])
{
    xqc_log_t *log = xqc_log_init(XQC_LOG_DEBUG, ".", "log");
    xqc_log_implement(log, XQC_LOG_DEBUG, "hello, %s", "world");
    xqc_log_debug(log, "alibaba %s", "taobao");
    xqc_log_debug(log, "1 min = %d secs", 60);
    xqc_log_release(log);
    return 0;
}

int test_array(int argc, char* argv[])
{
    xqc_array_t *a = xqc_array_create(xqc_default_allocator, 4, sizeof(int));
    int* p = xqc_array_push_n(a, 4);
    p[0] = 0; p[1] = 1; p[2] = 2; p[3] = 3;

    p = xqc_array_push_n(a, 2);
    p[0] = 4; p[1] = 5;

    p = xqc_array_push_n(a, 1);
    p[0] = 6;

    p = (int*)a->elts;
    for (unsigned i = 0; i < a->size; ++i) {
        printf("%d\n", p[i]);
    }

    xqc_array_destroy(a);

    return 0;
}

int test_pq(int argc, char* argv[])
{
    xqc_pq_t pq;
    if (xqc_pq_init(&pq, sizeof(unsigned long), 4, xqc_default_allocator, xqc_pq_default_cmp)) {
        printf("xqc_pq_init failed\n");
        return -1;
    }

    xqc_pq_push(&pq, 4);
    xqc_pq_push(&pq, 5);
    xqc_pq_push(&pq, 1);
    xqc_pq_push(&pq, 3);
    xqc_pq_push(&pq, 2);

    while (!xqc_pq_empty(&pq)) {
        xqc_pq_element_t* e = xqc_pq_top(&pq);
        printf("element key:%lu\n", (unsigned long)e->key);
        xqc_pq_pop(&pq);
    }

    xqc_pq_destroy(&pq);

    //-------------
    typedef struct xqc_pq_item_s
    {
        xqc_pq_key_t key;
        void* ptr;
    } xqc_pq_item_t;

    xqc_pq_t pq2;
    /* 从大到小出队 */
    //if (xqc_pq_init(&pq2, sizeof(xqc_pq_item_t), 4, xqc_default_allocator, xqc_pq_default_cmp)) {
    /* 从小到大出队 */
    if (xqc_pq_init(&pq2, sizeof(xqc_pq_item_t), 4, xqc_default_allocator, xqc_pq_revert_cmp)) {
        printf("xqc_pq_init failed\n");
        return -1;
    }

    int m = 300, n = 100, x = 400, y = 200, z = 500;

    xqc_pq_item_t* i1 = (xqc_pq_item_t*)xqc_pq_push(&pq2, 3);
    i1->ptr = &m;
    xqc_pq_item_t* i2 = (xqc_pq_item_t*)xqc_pq_push(&pq2, 1);
    i2->ptr = &n;
    xqc_pq_item_t* i3 = (xqc_pq_item_t*)xqc_pq_push(&pq2, 4);
    i3->ptr = &x;
    xqc_pq_item_t* i4 = (xqc_pq_item_t*)xqc_pq_push(&pq2, 2);
    i4->ptr = &y;
    xqc_pq_item_t* i5 = (xqc_pq_item_t*)xqc_pq_push(&pq2, 5);
    i5->ptr = &z;

    while (!xqc_pq_empty(&pq2)) {
        xqc_pq_item_t* e = (xqc_pq_item_t*)xqc_pq_top(&pq2);
        printf("element key:%lu value:%d\n", (unsigned long)e->key, *(int*)e->ptr);
        xqc_pq_pop(&pq2);
    }

    xqc_pq_destroy(&pq2);
    return 0;
}

typedef struct person_s
{
    int age;
    char name[20];
    xqc_queue_t queue;
    xqc_list_head_t list;
} person_t;

int test_queue(int argc, char* argv[])
{
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

    xqc_queue_t* pos;
    xqc_queue_foreach(pos, &q)
    {
        person_t* p = xqc_queue_data(pos, person_t, queue);
        printf("age=%d, name=%s\n", p->age, p->name);
    }

    printf("=================\n");

    xqc_queue_remove(&p3.queue);
    xqc_queue_foreach(pos, &q)
    {
        person_t* p = xqc_queue_data(pos, person_t, queue);
        printf("age=%d, name=%s\n", p->age, p->name);
    }

    return 0;
}

int test_hash(int argc, char* argv[])
{
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

    return 0;
}

typedef struct xqc_item_s
{
    xqc_object_id_t object_id;
    xqc_list_head_t list;
    int data;
} xqc_item_t;

static inline void test_object_manager_cb(xqc_object_t *o)
{
    xqc_item_t* item = (xqc_item_t*)o;
    printf("id:%u, data:%d\n", item->object_id, item->data);
}

int test_object_manager(int argc, char* argv[])
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

    printf("object manager used count:%d, free count:%d\n", 
            (int)xqc_object_manager_used_count(manager), 
            (int)xqc_object_manager_free_count(manager));

    xqc_object_manager_destroy(manager);

    return 0;
}

int test_list(int argc, char* argv[])
{
    person_t *pperson;
    person_t person_head;
    xqc_list_head_t *pos, *next;
    int i;

    // 初始化双链表的表头
    xqc_init_list_head(&person_head.list);

    // 添加节点
    for (i=0; i<5; i++)
    {
        pperson = (person_t*)malloc(sizeof(person_t));
        pperson->age = (i+1)*10;
        sprintf(pperson->name, "%d", i+1);
        // 将节点链接到链表的末尾
        // 如果想把节点链接到链表的表头后面，则使用 list_add
        xqc_list_add_tail(&(pperson->list), &(person_head.list));
    }

    // 遍历链表
    printf("==== 1st iterator d-link ====\n");
    xqc_list_for_each(pos, &person_head.list)
    {
        pperson = xqc_list_entry(pos, person_t, list);
        printf("name:%-2s, age:%d\n", pperson->name, pperson->age);
    }

    // 删除节点age为20的节点
    printf("==== delete node(age:20) ====\n");
    xqc_list_for_each_safe(pos, next, &person_head.list)
    {
        pperson = xqc_list_entry(pos, person_t, list);
        if(pperson->age == 20)
        {
            xqc_list_del_init(pos);
            free(pperson);
        }
    }
    return 0;
}

static inline void rbtree_cb(xqc_rbtree_node_t* node)
{
    printf("key=%lu\n", (unsigned long)node->key);
}

int test_rbtree(int argc, char* argv[])
{
    xqc_rbtree_t rbtree;
    xqc_rbtree_init(&rbtree);

    xqc_rbtree_node_t list[] = 
    {
        { 0, 0, 0, 5, xqc_rbtree_black },
        { 0, 0, 0, 1, xqc_rbtree_black },
        { 0, 0, 0, 4, xqc_rbtree_black },
        { 0, 0, 0, 7, xqc_rbtree_black },
        { 0, 0, 0, 8, xqc_rbtree_black },
        { 0, 0, 0, 9, xqc_rbtree_black },
        { 0, 0, 0, 2, xqc_rbtree_black },
        { 0, 0, 0, 0, xqc_rbtree_black },
        { 0, 0, 0, 3, xqc_rbtree_black },
        { 0, 0, 0, 6, xqc_rbtree_black },
    };

    for (size_t i = 0; i < sizeof(list)/sizeof(*list); ++i) {
        xqc_rbtree_insert(&rbtree, &list[i]);
    }

    xqc_rbtree_node_t* p = xqc_rbtree_find(&rbtree, 6);
    if (p) {
        printf("found 6\n");
    }

    p = xqc_rbtree_find(&rbtree, 16);
    if (!p) {
        printf("not found 16\n");
    }

    for (int i = 1; i < argc; ++i) {
        xqc_rbtree_delete(&rbtree, atoi(argv[i]));
    }

    xqc_rbtree_foreach(&rbtree, rbtree_cb);
    return 0;
}
