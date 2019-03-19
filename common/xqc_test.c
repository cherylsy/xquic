#include <stdio.h>

#include "xqc_memory_pool.h"
#include "xqc_id_hash.h"
#include "xqc_str_hash.h"
#include "xqc_log.h"
#include "xqc_list.h"
#include "xqc_array.h"
#include "xqc_priority_q.h"
#include "xqc_queue.h"

int test_memory_pool(int argc, char* argv[]);
int test_hash(int argc, char* argv[]);
int test_log(int argc, char* argv[]);
int test_list(int argc, char* argv[]);
int test_array(int argc, char* argv[]);
int test_pq(int argc, char* argv[]);
int test_queue(int argc, char* argv[]);

int main(int argc, char* argv[])
{
#if 0
    test_memory_pool(argc, argv);
#endif

#if 0
    test_hash(argc, argv);
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

int test_log(int argc, char* argv[])
{
    xqc_log_t *log = xqc_log_init();
    xqc_log_debug(log, "helloworld\n");
    xqc_log_debug(log, "arg=%d, name=%s\n", 10, "jiangyou");
    xqc_log_release(log);
    xqc_log(log, XQC_LOG_DEBUG, "hello, %s\n", "alibaba");
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
    if (xqc_pq_init(&pq, sizeof(unsigned long), 4, xqc_default_allocator)) {
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
        printf("element key:%lu\n", e->key);
        xqc_pq_pop(&pq);
    }

    xqc_pq_destroy(&pq);

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

