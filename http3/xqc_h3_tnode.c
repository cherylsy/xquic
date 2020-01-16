#include "xqc_h3_tnode.h"
#include "common/xqc_list.h"
#include "common/xqc_malloc.h"


int xqc_tnode_hash_create(xqc_tnode_hash_table_t * table, size_t element_count){
    if(element_count == 0){
        return -1;
    }
    table->element_count = element_count;
    table->list = xqc_malloc(sizeof(xqc_list_head_t) * element_count);

    if(table->list == NULL){
        return -1;
    }

    int i = 0;
    for(i = 0; i < element_count; i++){
        xqc_init_list_head(&table->list[i]);
    }
    return 0;
}

int xqc_tnode_hash_table_free_list(xqc_tnode_hash_table_t * table){

    xqc_free(table->list);
    return 0;
}

int xqc_tnode_hash_table_free_node(xqc_tnode_hash_table_t * table){
    xqc_list_head_t * list = table->list;
    int i = 0;
    for(i = 0; i < table->element_count; i++){
        xqc_list_head_t * head = &list[i];
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(pos, next, head){
            xqc_http3_tnode_t * tnode = xqc_list_entry(pos, xqc_http3_tnode_t, head_list);

            xqc_list_del(pos);
            xqc_free(tnode);
        }
    }
    return 0;
}

int xqc_tnode_free_hash_table(xqc_tnode_hash_table_t * table){
    xqc_tnode_hash_table_free_node(table);
    xqc_tnode_hash_table_free_list(table);
    return 0;
}

uint64_t xqc_tnode_hash_func(xqc_tnode_hash_table_t * table, uint64_t stream_id){
    if(table->element_count == 0){
        return 0;
    }
    return stream_id % (table->element_count);
}

xqc_http3_tnode_t * xqc_tnode_hash_find_by_id(xqc_tnode_hash_table_t * table, xqc_http3_node_id_t * nid){
    size_t index = xqc_tnode_hash_func(table, nid->id);
    xqc_list_head_t * head = &(table->list[index]);
    xqc_list_head_t * pos;
    xqc_http3_tnode_t * tnode;
    xqc_list_for_each(pos, head){
       tnode = xqc_list_entry( pos, xqc_http3_tnode_t, head_list);
       if(xqc_http3_node_id_eq(&tnode->nid, nid)){
           return tnode;
       }
    }
    return NULL;
}

int xqc_tnode_remove_from_hash(xqc_http3_tnode_t * tnode){
    xqc_list_head_t * head_list = &(tnode->head_list);
    xqc_list_del(head_list);
    head_list->next = &tnode->head_list;
    head_list->prev = &tnode->head_list;
    return 0;
}


int xqc_tnode_insert_to_hash(xqc_tnode_hash_table_t * table, xqc_http3_tnode_t * tnode){
    size_t index = xqc_tnode_hash_func(table, tnode->nid.id);
    xqc_list_head_t *head = &(table->list[index]);

    xqc_list_add(&tnode->head_list, head);
    return 0;
}

int xqc_http3_node_id_eq(xqc_http3_node_id_t * src, xqc_http3_node_id_t *dst){
    return (src->type == dst->type) && (src->id == dst->id);
    //return  (src->id == dst->id);
}

int xqc_http3_node_id_init(xqc_http3_node_id_t * nid, int type, uint64_t id){
    nid->type = type;
    nid->id = id;
    return 0;
}

xqc_http3_tnode_t * xqc_http3_create_tnode( xqc_tnode_hash_table_t * table, xqc_http3_node_id_t * nid, uint32_t weight, xqc_http3_tnode_t * parent){
    xqc_http3_tnode_t * tnode = xqc_malloc(sizeof(xqc_http3_tnode_t));
    if(tnode == NULL){
        return NULL;
    }
    xqc_http3_tnode_init(tnode, nid,  weight, parent);

    xqc_tnode_insert_to_hash(table, tnode);
    return tnode;
}

void xqc_http3_tnode_free(xqc_http3_tnode_t * tnode){

    if(tnode->parent){
        xqc_http3_tnode_del(tnode);
    }
    xqc_tnode_remove_from_hash(tnode);
    xqc_free(tnode);
}

int xqc_http3_tnode_init(xqc_http3_tnode_t * tnode, xqc_http3_node_id_t * nid, uint32_t weight, xqc_http3_tnode_t * parent){

    tnode->parent = parent;
    tnode->first_child = NULL;
    //tnode->num_children = 0;

    if(parent){
        tnode->next_sibling = parent->first_child;
        parent->first_child = tnode;
        //++parent->num_children;
    }else{//root node's parent is NULL
        tnode->next_sibling = NULL;
    }

    tnode->nid = *nid;
    tnode->weight = weight;

    //tnode->h3_stream = NULL;
    return 0;

}


int xqc_http3_tnode_insert(xqc_http3_tnode_t * tnode, xqc_http3_tnode_t * parent){

    tnode->next_sibling = parent->first_child;
    parent->first_child = tnode;
    tnode->parent = parent;
    //++parent->num_children;
    return 0;
}


int xqc_http3_tnode_insert_exclusive(xqc_http3_tnode_t *tnode, xqc_http3_tnode_t *parent){

    xqc_http3_tnode_t **p, *node;
    for(node = parent->first_child; node != NULL; node = node->next_sibling){

        node->parent = tnode;
    }

    for (p = &tnode->first_child; *p; p = &(*p)->next_sibling);

    *p = parent->first_child;
    parent->first_child = NULL;
    //tnode->num_children += parent->num_children;
    //parent->num_children = 0;

    xqc_http3_tnode_insert(tnode, parent);

    return 0;
}


int xqc_http3_tnode_handle_child(xqc_http3_tnode_t * parent, xqc_http3_tnode_t * child){

    xqc_http3_tnode_t * tnode = NULL;
    xqc_http3_tnode_t * last_tnode = NULL;
    tnode = parent->first_child;
    if(tnode == NULL){//means parent no child
        parent->first_child = child;
    }else{
        for(; tnode; tnode = tnode->next_sibling){
            last_tnode = tnode;
        }
        last_tnode->next_sibling = child;
    }

    tnode = child;
    for(; tnode; tnode = tnode->next_sibling){

        tnode->parent = parent;
        //++parent->num_children;
    }
    return 0;
}

int xqc_http3_tnode_del(xqc_http3_tnode_t * tnode){

    xqc_http3_tnode_t * parent = tnode->parent;

    if(parent == NULL){

        return 0;
    }

    xqc_http3_tnode_t **p;

    for(p = &(parent->first_child); *p != tnode; p = &((*p)->next_sibling));

    *p = tnode->next_sibling;

    xqc_http3_tnode_handle_child(parent, tnode->first_child);
    tnode->parent = NULL;
    tnode->next_sibling = NULL;
    //--parent->num_children;

    return 0;
}

int xqc_http3_tnode_remove_tree(xqc_http3_tnode_t *tnode){

    xqc_http3_tnode_t * parent = tnode->parent;

    if(parent == NULL){

        return 0;
    }

    xqc_http3_tnode_t **p;

    for(p = &(parent->first_child); *p != tnode; p = &((*p)->next_sibling));

    *p = tnode->next_sibling;

    //xqc_http3_tnode_handle_child(parent, tnode->first_child);
    tnode->parent = NULL;
    tnode->next_sibling = NULL;
    //--parent->num_children;
    return 0;
}


xqc_http3_tnode_t * xqc_http3_tnode_find_nid(xqc_http3_tnode_t * root, xqc_http3_node_id_t * nid){

    xqc_http3_tnode_t * tnode = NULL;
    //tnode = root->first_child;
    for(tnode = root->first_child; tnode; tnode = tnode->next_sibling){
        if(xqc_http3_node_id_eq(&tnode->nid, nid)){
            return tnode;
        }

        xqc_http3_tnode_t * tmp_tnode = xqc_http3_tnode_find_nid(tnode, nid);
        if(tmp_tnode)return tmp_tnode;
    }

    return NULL;
}

