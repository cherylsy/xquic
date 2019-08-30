#ifndef _XQC_H3_FRAME_H_INCLUDED_
#define _XQC_H3_FRAME_H_INCLUDED_

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
  XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE,
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
  XQC_HTTP3_REQ_STREAM_STATE_FRAME_TYPE,
  XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH,
  XQC_HTTP3_REQ_STREAM_STATE_DATA,
  XQC_HTTP3_REQ_STREAM_STATE_HEADERS,
  XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID,
  XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE,
  XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH,
  XQC_HTTP3_REQ_STREAM_STATE_IGN_FRAME,
} xqc_http3_req_stream_state;

typedef enum {
  XQC_HTTP3_PUSH_STREAM_STATE_FRAME_TYPE,
  XQC_HTTP3_PUSH_STREAM_STATE_FRAME_LENGTH,
  XQC_HTTP3_PUSH_STREAM_STATE_DATA,
  XQC_HTTP3_PUSH_STREAM_STATE_HEADERS,
  XQC_HTTP3_PUSH_STREAM_STATE_IGN_FRAME,
  XQC_HTTP3_PUSH_STREAM_STATE_PUSH_ID,
  XQC_HTTP3_PUSH_STREAM_STATE_IGN_REST,
} xqc_http3_push_stream_state;

typedef struct{
    int64_t type;
    int64_t length;
}xqc_http3_frame_hd;

typedef struct {
    xqc_http3_frame_hd hd;
} xqc_http3_frame_data;



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

typedef struct {
  xqc_http3_frame_hd hd;
  size_t niv;
  xqc_http3_settings_entry iv[1];
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

#endif /* _XQC_H3_FRAME_H_INCLUDED_ */
