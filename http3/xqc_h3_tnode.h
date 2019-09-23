#ifndef __XQC_H3_TNODE_H__
#define __XQC_H3_TNODE_H__

#if 0
typedef enum {
  XQC_HTTP3_PRI_ELEM_TYPE_REQUEST = 0x00,
  XQC_HTTP3_PRI_ELEM_TYPE_PUSH = 0x01,
  XQC_HTTP3_PRI_ELEM_TYPE_PLACEHOLDER = 0x02
} xqc_http3_pri_elem_type;

typedef enum {
  XQC_HTTP3_ELEM_DEP_TYPE_REQUEST = 0x00,
  XQC_HTTP3_ELEM_DEP_TYPE_PUSH = 0x01,
  XQC_HTTP3_ELEM_DEP_TYPE_PLACEHOLDER = 0x02,
  XQC_HTTP3_ELEM_DEP_TYPE_ROOT = 0x03
} xqc_http3_elem_dep_type;
#endif

#define XQC_HTTP3_DEFAULT_WEIGHT 16
#define XQC_HTTP3_MAX_WEIGHT 256

#define XQC_TNODE_HASH_SIZE 32

typedef enum {
  /* Use the same value with xqc_http3_elem_dep_type. */
  XQC_HTTP3_NODE_ID_TYPE_STREAM = XQC_HTTP3_ELEM_DEP_TYPE_REQUEST,
  XQC_HTTP3_NODE_ID_TYPE_PUSH = XQC_HTTP3_ELEM_DEP_TYPE_PUSH,
  XQC_HTTP3_NODE_ID_TYPE_PLACEHOLDER = XQC_HTTP3_ELEM_DEP_TYPE_PLACEHOLDER,
  XQC_HTTP3_NODE_ID_TYPE_ROOT = XQC_HTTP3_ELEM_DEP_TYPE_ROOT,
  /* XQC_HTTP3_NODE_ID_TYPE_UT is defined for unit test */
  XQC_HTTP3_NODE_ID_TYPE_UT = 0xff,
} xqc_http3_node_id_type_t;

typedef struct {
  xqc_http3_node_id_type_t type;
  int64_t stream_id;
} xqc_http3_node_id_t;

typedef struct xqc_http3_tnode{
    xqc_list_head_t  head_list;

    struct xqc_http3_tnode * parent;
    struct xqc_http3_tnode * first_child;
    struct xqc_http3_tnode * next_sibling;
    //uint32_t num_children;

    uint32_t weight;
    //uint64_t seq;

    xqc_http3_node_id_t     nid;

    xqc_h3_stream_t * h3_stream;

}xqc_http3_tnode_t;


typedef struct xqc_tnode_hash_table{
    xqc_list_head_t * list;
    size_t element_count;
}xqc_tnode_hash_table_t;

#endif
