#ifndef _XQC_STR_HASH_INCLUDED_
#define _XQC_STR_HASH_INCLUDED_

#include <stdint.h>

#include "src/common/xqc_str.h"

/*
 * 哈希表元素
 * */
typedef struct xqc_str_hash_element_s
{
    uint64_t hash; /*hash，用于对桶数取模*/
    xqc_str_t str; /*字符串，仅仅比较hash还不够，还需要比较字符串*/
    void *value; /*关联的元素数据*/
} xqc_str_hash_element_t;

/*
 * hash冲突链节点
 * */
typedef struct xqc_str_hash_node_s
{
    struct xqc_str_hash_node_s *next; /*冲突链*/
    xqc_str_hash_element_t element; /*节点元素*/
} xqc_str_hash_node_t;

/*
 * hash表
 * */
typedef struct xqc_str_hash_table_s
{
    xqc_str_hash_node_t **list; /*桶列表*/
    size_t count; /*桶的数目*/

    xqc_allocator_t allocator; /*内存配置器*/
} xqc_str_hash_table_t;

/*
 * 哈希表初始化
 * */
static inline int xqc_str_hash_init(xqc_str_hash_table_t* hash_tab,  xqc_allocator_t allocator, size_t bucket_num)
{
    hash_tab->allocator = allocator;
    hash_tab->list = allocator.malloc(allocator.opaque, sizeof(xqc_str_hash_node_t*) * bucket_num);
    xqc_memzero(hash_tab->list, sizeof(xqc_str_hash_node_t*) * bucket_num);
    if (hash_tab->list == NULL) {
        return XQC_ERROR;
    }
    hash_tab->count = bucket_num;
    return XQC_OK;
}

/*
 * 哈希表释放
 * */
static inline void xqc_str_hash_release(xqc_str_hash_table_t* hash_tab)
{
    xqc_allocator_t* a = &hash_tab->allocator;
    for (size_t i = 0; i < hash_tab->count; ++i) {
        xqc_str_hash_node_t* node = hash_tab->list[i];
        while (node) {
            xqc_str_hash_node_t* p = node;
            node = node->next;
            a->free(a->opaque, p);
        }
    }
    a->free(a->opaque, hash_tab->list);
}

/*
 * 查找
 * */
static inline void* xqc_str_hash_find(xqc_str_hash_table_t* hash_tab, uint64_t hash, xqc_str_t str)
{
    uint64_t index = hash % hash_tab->count;
    xqc_str_hash_node_t* node = hash_tab->list[index];
    while (node) {
        if (node->element.hash == hash && xqc_str_equal(str, node->element.str)) {
            return node->element.value;
        }
        node = node->next;
    }
    return NULL;
}

/*
 * 添加元素
 * */
static inline int xqc_str_hash_add(xqc_str_hash_table_t* hash_tab, xqc_str_hash_element_t e)
{
    uint64_t index = e.hash % hash_tab->count;
    xqc_allocator_t* a = &hash_tab->allocator;
    xqc_str_hash_node_t* node = a->malloc(a->opaque, sizeof(xqc_str_hash_node_t));
    if (node == NULL) {
        return XQC_ERROR;
    }

    node->element = e;
    node->element.str.data = a->malloc(a->opaque, e.str.len);
    if (node->element.str.data == NULL) {
        a->free(a->opaque, node);
        return XQC_ERROR;
    }
    xqc_memcpy(node->element.str.data, e.str.data, e.str.len);
    node->element.str.len = e.str.len;
    
    node->next = hash_tab->list[index];
    hash_tab->list[index] = node;

    return XQC_OK;
}

/*
 * 删除元素
 * */
static inline int xqc_str_hash_delete(xqc_str_hash_table_t* hash_tab, uint64_t hash, xqc_str_t str)
{
    uint64_t index = hash % hash_tab->count;
    xqc_allocator_t* a = &hash_tab->allocator;
    xqc_str_hash_node_t** pp = &hash_tab->list[index];
    xqc_str_hash_node_t* node = hash_tab->list[index];
    while (node) {
        if (node->element.hash == hash && xqc_str_equal(str, node->element.str)) {
            *pp = node->next; /*从冲突链删除*/
            a->free(a->opaque, node->element.str.data);
            a->free(a->opaque, node);
            return XQC_OK;
        }

        pp = &node->next;
        node = node->next;
    }

    return XQC_ERROR;
}

#endif /*_XQC_STR_HASH_INCLUDED_*/
