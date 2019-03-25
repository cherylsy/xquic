#ifndef _XQC_RBTREE_H_INCLUDED_
#define _XQC_RBTREE_H_INCLUDED_

#include <stdint.h>

#include "xqc_malloc.h"

typedef enum xqc_rbtree_color_e
{
    xqc_rbtree_red,
    xqc_rbtree_black,
} xqc_rbtree_color_t;

typedef uint64_t xqc_rbtree_key_t;

typedef struct xqc_rbtree_node_s
{
    struct xqc_rbtree_node_s *parent;
    struct xqc_rbtree_node_s *left;
    struct xqc_rbtree_node_s *right;
    xqc_rbtree_key_t key;
    xqc_rbtree_color_t color;
    char data[0];
} xqc_rbtree_node_t;

typedef struct xqc_rbtree_s
{
    xqc_rbtree_node_t *root;
    xqc_allocator_t a;
} xqc_rbtree_t;

static inline xqc_rbtree_t* xqc_rbtree_create(xqc_allocator_t a)
{
    xqc_rbtree_t* rbtree = a.malloc(a.opaque, sizeof(*rbtree));
    if (rbtree == NULL) {
        return NULL;
    }

    rbtree->root = NULL;
    rbtree->a = a;
    return rbtree;
}

static inline void xqc_rbtree_destroy(xqc_rbtree_t* rbtree)
{
    xqc_allocator_t a = rbtree->a;
    a.free(a.opaque, rbtree);
}

static inline xqc_rbtree_node_t* xqc_rbtree_find(xqc_rbtree_t* rbtree, xqc_rbtree_key_t key)
{
    xqc_rbtree_node_t *node = rbtree->root;
    while (node) {
        if (key < node->key) {
            node = node->left;
        } else if (node->key < key) {
            node = node->right;
        } else {
            return node;
        }
    }
    return NULL;
}

static inline void xqc_rbtree_rotate_left(xqc_rbtree_t* rbtree, xqc_rbtree_node_t* x)
{
    xqc_rbtree_node_t* y = x->right;
    x->right = y->left;
    y->left->parent = x;
    y->parent = x->parent;

    if (x->parent == NULL) {
        rbtree->root = y;
    } else if (x == x->parent->left) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }

    y->left = x;
    x->parent = y;
}

static inline void xqc_rbtree_rotate_right(xqc_rbtree_t* rbtree, xqc_rbtree_node_t* y)
{
    xqc_rbtree_node_t* x = y->left;
    y->left = x->right;
    x->right->parent = y;
    x->parent = y->parent;

    if (y->parent == NULL) {
        rbtree->root = x;
    } else if (y == y->parent->right) {
        y->parent->right = x;
    } else {
        y->parent->left = x;
    }

    x->right = y;
    y->parent = x;
}

static inline void xqc_rbtree_insert_fixup(xqc_rbtree_t* rbtree, xqc_rbtree_node_t* x)
{
    while (x != rbtree->root && x->parent->color == xqc_rbtree_red) {
        if (x->parent == x->parent->parent->left) { /*父节点为祖父节点的左子树*/
            /*叔父节点*/
            xqc_rbtree_node_t* y = x->parent->parent->right; 

            if (y->color == xqc_rbtree_red) { /*叔父节点为红*/
                /*case 1*/
                x->parent->color = xqc_rbtree_black;
                y->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                x = x->parent->parent;
            } else { /*叔父节点为黑*/
                if (x == x->parent->right) {
                    /*case 2*/
                    x = x->parent;
                    xqc_rbtree_rotate_left(rbtree, x);
                }

                /*case 3*/
                x->parent->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                xqc_rbtree_rotate_right(rbtree, x->parent->parent);
            }
        } else {
            /*叔父节点*/
            xqc_rbtree_node_t* y = x->parent->parent->left; 

            if (y->color == xqc_rbtree_red) { /*叔父节点为红*/
                /*case 4*/
                x->parent->color = xqc_rbtree_black;
                y->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                x = x->parent->parent;
            } else { /*叔父节点为黑*/
                if (x == x->parent->left) {
                    /*case 5*/
                    x = x->parent;
                    xqc_rbtree_rotate_right(rbtree, x);
                } 

                /*case 6*/
                x->parent->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                xqc_rbtree_rotate_left(rbtree, x->parent->parent);
            }
        }
    }

    rbtree->root->color = xqc_rbtree_black;
}

static inline int xqc_rbtree_insert(xqc_rbtree_t* rbtree, xqc_rbtree_key_t key, const void *data, size_t data_len)
{
    xqc_rbtree_node_t* p = NULL;
    xqc_rbtree_node_t* x = rbtree->root;
    while (x != NULL) {
        p = x;
        if (key < x->key) {
            x = x->left;
        } else if (x->key < key) {
            x = x->right;
        } else {
            return 1; /*key重复，插入失败*/
        }
    }

    xqc_allocator_t a = rbtree->a;
    xqc_rbtree_node_t *n = a.malloc(a.opaque, sizeof(xqc_rbtree_node_t) + data_len);

    n->parent = p;
    n->left = NULL;
    n->right = NULL;
    n->key = key;
    n->color = xqc_rbtree_red;
    memcpy(n->data, data, data_len); /*copy data*/

    if (p == NULL) {
        rbtree->root = n;
    } else if (key < p->key) {
        p->left = n;
    } else {
        p->right = n;
    }

    xqc_rbtree_insert_fixup(rbtree, n);

    return 0;
}

static inline int xqc_rbtree_delete(xqc_rbtree_t* rbtree, xqc_rbtree_key_t key)
{
    return 0;
}

static inline void xqc_rbtree_infix_order(xqc_rbtree_node_t* node)
{
    if (node->left) {
        xqc_rbtree_infix_order(node->left);
    }

    printf("%lu\n", (unsigned long)node->key);

    if (node->right) {
        xqc_rbtree_infix_order(node->right);
    }
}

static inline void xqc_rbtree_foreach(xqc_rbtree_t* rbtree)
{
    xqc_rbtree_node_t* root = rbtree->root;
    if (root) {
        xqc_rbtree_infix_order(root);
    }
}

#endif /*_XQC_RBTREE_H_INCLUDED_*/
