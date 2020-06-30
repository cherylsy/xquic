#ifndef _XQC_H_LIST_INCLUED_
#define _XQC_H_LIST_INCLUED_


#include <stddef.h>
#include <assert.h>
#include "xqc_common.h"

#define XQC_LIST_POISON1  ((void *) 0x1)
#define XQC_LIST_POISON2  ((void *) 0x2)

/*
 * 参考linux内核链表的实现
 * 任何需要用链表串起来的结构，内嵌xqc_list_head_t即可用链表串起来，非常方便
 * 具体用法参考xqc_test.c文件的test_list()
 * 以__开头的函数是内部实现。
 * 需要关注的接口：
 * 初始化：xqc_list_head_init(), xqc_init_list_head()
 * 增：xqc_list_add(), xqc_list_add_tail()
 * 删：xqc_list_del(), xqc_list_del_init()
 * 替换：xqc_list_replace()
 * 判空：xqc_list_empty()
 * 遍历：xqc_list_for_each(), xqc_list_for_each_safe()
 * 取出元素：xqc_list_entry()
 * */

typedef struct xqc_list_head_s
{
    struct xqc_list_head_s *prev, *next;
} xqc_list_head_t;

#define xqc_list_head_init(name) { &(name), &(name) }

#if GNU11
# define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#else
# define container_of(ptr, type, member) (type *)( (char *)ptr - offsetof(type, member) )
#endif

#define xqc_list_entry(ptr, type, member) container_of(ptr, type, member)

static inline void xqc_init_list_head(xqc_list_head_t *list)
{
    list->prev = list;
    list->next = list;
}

static inline int __xqc_list_add_valid(xqc_list_head_t *node, xqc_list_head_t *prev, xqc_list_head_t *next)
{
    assert(next->prev == prev && prev->next == next && node != prev && node != next);

    if (next->prev != prev || prev->next != next || node == prev || node == next) {
        return XQC_FALSE;
    }
    return XQC_TRUE;
}

static inline int __xqc_list_del_entry_valid(xqc_list_head_t *entry)
{
    xqc_list_head_t *prev, *next;

    prev = entry->prev;
    next = entry->next;

    assert(prev != NULL && next != NULL);
    assert(next != XQC_LIST_POISON1 
           && prev != XQC_LIST_POISON2
           && prev->next == entry 
           && next->prev == entry);

    if (prev == NULL || next == NULL) {
        return XQC_FALSE;
    }
    if (next == XQC_LIST_POISON1 || prev == XQC_LIST_POISON2 || prev->next != entry || next->prev != entry) {
        return XQC_FALSE;
    }
    return XQC_TRUE;
}

static inline void __xqc_list_add(xqc_list_head_t *node, xqc_list_head_t *prev, xqc_list_head_t *next)
{
    if (!__xqc_list_add_valid(node, prev, next)) {
        return;
    }
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

static inline void xqc_list_add(xqc_list_head_t *node, xqc_list_head_t *head)
{
    __xqc_list_add(node, head, head->next);
}

static inline void xqc_list_add_tail(xqc_list_head_t *node, xqc_list_head_t *head)
{
    __xqc_list_add(node, head->prev, head);
}

static inline void __xqc_list_del(xqc_list_head_t * prev, xqc_list_head_t * next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void __xqc_list_del_entry(xqc_list_head_t *entry)
{
    if (!__xqc_list_del_entry_valid(entry)) {
        return;
    }
    __xqc_list_del(entry->prev, entry->next);
}

static inline void xqc_list_del(xqc_list_head_t *entry)
{
    __xqc_list_del_entry(entry);
    entry->next = XQC_LIST_POISON1;
    entry->prev = XQC_LIST_POISON2;
}

static inline void xqc_list_del_init(xqc_list_head_t *entry)
{
    __xqc_list_del_entry(entry);
    xqc_init_list_head(entry);
}

static inline void xqc_list_replace(xqc_list_head_t *old, xqc_list_head_t *node)
{
    node->next = old->next;
    node->next->prev = node;
    node->prev = old->prev;
    node->prev->next = node;
}

static inline int xqc_list_empty(const xqc_list_head_t *head)
{
    return head->next == head;
}

#define xqc_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define xqc_list_for_each_from(pos, head) \
    for (; pos != (head); pos = pos->next)

#define xqc_list_for_each_reverse(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define xqc_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; \
        pos != (head); \
        pos = n, n = pos->next)

#endif /*_XQC_H_LIST_INCLUED_*/
