#ifndef _XQC_H3_FRAME_H_INCLUDED_
#define _XQC_H3_FRAME_H_INCLUDED_

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <xquic/xquic.h>
#include "src/http3/xqc_h3_tnode.h"

typedef struct xqc_h3_stream_s xqc_h3_stream_t;
typedef struct xqc_h3_conn_s xqc_h3_conn_t;

typedef enum {
    XQC_HTTP3_FRAME_DATA = 0x00,
    XQC_HTTP3_FRAME_HEADERS = 0x01,
    XQC_HTTP3_FRAME_PRIORITY = 0x02,
    XQC_HTTP3_FRAME_CANCEL_PUSH = 0x03,
    XQC_HTTP3_FRAME_SETTINGS = 0x04,
    XQC_HTTP3_FRAME_PUSH_PROMISE = 0x05,
    XQC_HTTP3_FRAME_GOAWAY = 0x07,
    XQC_HTTP3_FRAME_MAX_PUSH_ID = 0x0d,
    XQC_HTTP3_FRAME_DUPLICATE_PUSH = 0x0e,
} xqc_http3_frame_type;


typedef enum {
  XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE = 0,
  XQC_HTTP3_CTRL_STREAM_STATE_FRAME_LENGTH,
  XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY,
  XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_PRI_ELEM_ID,
  XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_ELEM_DEP_ID,
  XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_WEIGHT,
  XQC_HTTP3_CTRL_STREAM_STATE_CANCEL_PUSH,
  XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS,
  XQC_HTTP3_CTRL_STREAM_STATE_GOAWAY,
  XQC_HTTP3_CTRL_STREAM_STATE_MAX_PUSH_ID,
  XQC_HTTP3_CTRL_STREAM_STATE_IGN_FRAME,
  XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_ID,
  XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE,
} xqc_http3_ctrl_stream_state;

typedef enum {
  XQC_HTTP3_REQ_STREAM_STATE_FRAME_TYPE = 0,
  XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH,
  XQC_HTTP3_REQ_STREAM_STATE_DATA,
  XQC_HTTP3_REQ_STREAM_STATE_HEADERS,
  XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID,
  XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE,
  XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH,
  XQC_HTTP3_REQ_STREAM_STATE_IGN_FRAME,
} xqc_http3_req_stream_state;

typedef enum {
  XQC_HTTP3_PUSH_STREAM_STATE_FRAME_TYPE = 0,
  XQC_HTTP3_PUSH_STREAM_STATE_FRAME_LENGTH,
  XQC_HTTP3_PUSH_STREAM_STATE_DATA,
  XQC_HTTP3_PUSH_STREAM_STATE_HEADERS,
  XQC_HTTP3_PUSH_STREAM_STATE_IGN_FRAME,
  XQC_HTTP3_PUSH_STREAM_STATE_PUSH_ID,
  XQC_HTTP3_PUSH_STREAM_STATE_IGN_REST,
} xqc_http3_push_stream_state;

#define XQC_MAX_FRAME_SIZE (4*1024)

typedef struct{
    int64_t type;
    int64_t length;
}xqc_http3_frame_hd;

typedef struct {
    xqc_http3_frame_hd hd;
} xqc_http3_frame_data;

typedef struct xqc_h3_data_buf{
    xqc_list_head_t list_head;
    size_t  buf_len;
    size_t  data_len;
    //size_t  data_left;
    size_t  already_consume;
    uint8_t fin_flag; //xqc_h3_data_buf_fin_flag_t
    char    data[];

}xqc_h3_data_buf_t;

typedef xqc_h3_data_buf_t xqc_h3_frame_send_buf_t;
typedef xqc_h3_data_buf_t xqc_data_buf_t;



/**
 * @struct
 *
 * :type:`xqc_http3_nv` is the name/value pair, which mainly used to
 * represent header fields.
 */
typedef struct {
  /**
   * name is the header field name.
   */
  uint8_t *name;
  /**
   * value is the header field value.
   */
  uint8_t *value;
  /**
   * namelen is the length of the |name|, excluding terminating NULL.
   */
  size_t namelen;
  /**
   * valuelen is the length of the |value|, excluding terminating
   * NULL.
   */
  size_t valuelen;
  /**
   * flags is bitwise OR of one or more of :type:`xqc_http3_nv_flag`.
   */
  uint8_t flags;
} xqc_http3_nv;

typedef struct {
  xqc_http3_frame_hd hd;
  xqc_http3_nv *nva;
  size_t nvlen;
} xqc_http3_frame_headers;



typedef struct {
  xqc_http3_frame_hd hd;
  xqc_http3_pri_elem_type pt;
  xqc_http3_elem_dep_type dt;
  int64_t pri_elem_id;
  int64_t elem_dep_id;
  uint32_t weight;
  uint8_t exclusive;
} xqc_http3_frame_priority;

typedef struct {
  xqc_http3_frame_hd hd;
  int64_t push_id;
} xqc_http3_frame_cancel_push;

typedef enum {
  XQC_HTTP3_SETTINGS_ID_MAX_HEADER_LIST_SIZE = 0x06,
  XQC_HTTP3_SETTINGS_ID_NUM_PLACEHOLDERS = 0x09,
  XQC_HTTP3_SETTINGS_ID_QPACK_MAX_TABLE_CAPACITY = 0x01,
  XQC_HTTP3_SETTINGS_ID_QPACK_BLOCKED_STREAMS = 0x07,
} xqc_http3_settings_id;

typedef struct {
  uint64_t id;
  uint64_t value;
} xqc_http3_settings_entry;

#define MAX_SETTING_ENTRY 16
typedef struct {
  xqc_http3_frame_hd hd;
  size_t niv;
  xqc_http3_settings_entry iv[MAX_SETTING_ENTRY];
} xqc_http3_frame_settings;

typedef struct {
  xqc_http3_frame_hd hd;
  xqc_http3_nv *nva;
  size_t nvlen;
  int64_t push_id;
} xqc_http3_frame_push_promise;

typedef struct {
  xqc_http3_frame_hd hd;
  int64_t stream_id;
} xqc_http3_frame_goaway;

typedef struct {
  xqc_http3_frame_hd hd;
  int64_t push_id;
} xqc_http3_frame_max_push_id;

typedef struct {
  xqc_http3_frame_hd hd;
  int64_t push_id;
} xqc_http3_frame_duplicate_push;


typedef union {
  xqc_http3_frame_hd hd;
  xqc_http3_frame_data data;
  xqc_http3_frame_headers headers;
  xqc_http3_frame_priority priority;
  xqc_http3_frame_cancel_push cancel_push;
  xqc_http3_frame_settings settings;
  xqc_http3_frame_push_promise push_promise;
  xqc_http3_frame_goaway goaway;
  xqc_http3_frame_max_push_id max_push_id;
  xqc_http3_frame_duplicate_push duplicate_push;
} xqc_http3_frame;



typedef struct {
    int64_t acc;
    size_t left;
} xqc_http3_varint_read_state;

typedef struct {
    xqc_http3_varint_read_state rvint;
    xqc_http3_frame fr;
    int state;
    int64_t left;
} xqc_http3_stream_read_state;


typedef struct {
  uint64_t max_header_list_size;
  uint64_t num_placeholders;
  uint64_t max_pushes;
  uint64_t qpack_max_table_capacity;
  uint64_t qpack_blocked_streams;
} xqc_http3_conn_settings;

typedef struct { //把这个结构体简化下
    xqc_http3_frame fr;

    union{
        struct {
            xqc_http3_conn_settings *local_settings;
        }settings;
        struct {
            char * data;
            size_t data_len;
        }data;
    }aux;
}xqc_http3_frame_entry_t;



int xqc_http3_stream_write_settings(xqc_h3_stream_t * h3_stream, xqc_http3_conn_settings * settings );

ssize_t xqc_http3_write_frame_data(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len, uint8_t fin);

ssize_t xqc_http3_write_frame_header(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len, uint8_t fin);

ssize_t xqc_http3_conn_read_control(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen);

ssize_t xqc_http3_conn_read_bidi(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, uint8_t fin);

int xqc_h3_send_frame_buffer(xqc_h3_stream_t * h3_stream, xqc_list_head_t * head);

int xqc_h3_stream_free_data_buf(xqc_h3_stream_t *h3_stream);

ssize_t xqc_http3_write_headers(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers, uint8_t fin);

ssize_t xqc_http3_conn_read_uni( xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, int fin);
ssize_t xqc_http3_qpack_encoder_stream_send(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len);

int xqc_h3_uni_stream_write_stream_type(xqc_h3_stream_t * h3_stream, uint8_t stream_type);
int xqc_buf_to_tail(xqc_list_head_t * phead , char * data, int data_len, uint8_t fin);
int xqc_http3_handle_recv_data_buf(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream);

xqc_data_buf_t * xqc_create_data_buf(int buf_size, int data_len);
#endif /* _XQC_H3_FRAME_H_INCLUDED_ */
