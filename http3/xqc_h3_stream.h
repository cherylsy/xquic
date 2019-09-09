#ifndef _XQC_H3_STREAM_H_INCLUDED_
#define _XQC_H3_STREAM_H_INCLUDED_

#include "include/xquic.h"
#include "include/xquic_typedef.h"
#include "xqc_h3_conn.h"
#include "xqc_h3_frame.h"

typedef enum {
    XQC_H3_STREAM_REQUEST,
    XQC_H3_STREAM_CONTROL,
    XQC_H3_STREAM_PUSH,
    XQC_H3_STREAM_NUM,
} xqc_h3_stream_type_t;

typedef struct xqc_h3_conn_s xqc_h3_conn_t;
typedef struct xqc_h3_stream_s xqc_h3_stream_t;

/* xqc_http3_stream_type is unidirectional stream type. */
typedef enum {
    XQC_HTTP3_STREAM_TYPE_CONTROL = 0x00,
    XQC_HTTP3_STREAM_TYPE_PUSH = 0x01,
    XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER = 0x02,
    XQC_HTTP3_STREAM_TYPE_QPACK_DECODER = 0x03,
    XQC_HTTP3_STREAM_TYPE_UNKNOWN = UINT64_MAX,
} xqc_http3_stream_type;


typedef enum {
    XQC_HTTP3_STREAM_FLAG_NONE = 0x0000,
    XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED = 0x0001,
    /* XQC_HTTP3_STREAM_FLAG_FC_BLOCKED indicates that stream is
       blocked by QUIC flow control. */
    XQC_HTTP3_STREAM_FLAG_FC_BLOCKED = 0x0002,
    /* XQC_HTTP3_STREAM_FLAG_READ_DATA_BLOCKED indicates that application
       is temporarily unable to provide data. */
    XQC_HTTP3_STREAM_FLAG_READ_DATA_BLOCKED = 0x0004,
    /* XQC_HTTP3_STREAM_FLAG_WRITE_END_STREAM indicates that application
       finished to feed outgoing data. */
    XQC_HTTP3_STREAM_FLAG_WRITE_END_STREAM = 0x0008,
    /* XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED indicates that stream is
       blocked due to QPACK decoding. */
    XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED = 0x0010,
    /* XQC_HTTP3_STREAM_FLAG_READ_EOF indicates that remote endpoint sent
       fin. */
    XQC_HTTP3_STREAM_FLAG_READ_EOF = 0x0020,
    /* XQC_HTTP3_STREAM_FLAG_CLOSED indicates that QUIC stream was closed.
       nghttp3_stream object can still alive because it might be blocked
       by QPACK decoder. */
    XQC_HTTP3_STREAM_FLAG_CLOSED = 0x0040,
    /* XQC_HTTP3_STREAM_FLAG_PUSH_PROMISE_BLOCKED indicates that stream is
       blocked because the corresponding PUSH_PROMISE has not been
       received yet. */
    XQC_HTTP3_STREAM_FLAG_PUSH_PROMISE_BLOCKED = 0x0080,
    /* XQC_HTTP3_STREAM_FLAG_CTRL_PRIORITY_APPLIED indicates that stream
       has been prioritized by PRIORITY frame received in control
       stream. */
    XQC_HTTP3_STREAM_FLAG_CTRL_PRIORITY_APPLIED = 0x0100,
    /* XQC_HTTP3_STREAM_FLAG_RESET indicates that stream is reset. */
    XQC_HTTP3_STREAM_FLAG_RESET = 0x0200,
} xqc_http3_stream_flag;


typedef enum {
  XQC_HTTP3_HTTP_STATE_NONE,
  XQC_HTTP3_HTTP_STATE_REQ_INITIAL,
  XQC_HTTP3_HTTP_STATE_REQ_BEGIN,
  XQC_HTTP3_HTTP_STATE_REQ_PRIORITY_BEGIN,
  XQC_HTTP3_HTTP_STATE_REQ_PRIORITY_END,
  XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN,
  XQC_HTTP3_HTTP_STATE_REQ_HEADERS_END,
  XQC_HTTP3_HTTP_STATE_REQ_DATA_BEGIN,
  XQC_HTTP3_HTTP_STATE_REQ_DATA_END,
  XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN,
  XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_END,
  XQC_HTTP3_HTTP_STATE_REQ_END,
  XQC_HTTP3_HTTP_STATE_RESP_INITIAL,
  XQC_HTTP3_HTTP_STATE_RESP_BEGIN,
  XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN,
  XQC_HTTP3_HTTP_STATE_RESP_HEADERS_END,
  XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN,
  XQC_HTTP3_HTTP_STATE_RESP_DATA_END,
  XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN,
  XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_END,
  XQC_HTTP3_HTTP_STATE_RESP_END,
} xqc_http3_stream_http_state;

typedef enum {
    XQC_HTTP3_HTTP_EVENT_DATA_BEGIN,
    XQC_HTTP3_HTTP_EVENT_DATA_END,
    XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN,
    XQC_HTTP3_HTTP_EVENT_HEADERS_END,
    XQC_HTTP3_HTTP_EVENT_PUSH_PROMISE_BEGIN,
    XQC_HTTP3_HTTP_EVENT_PUSH_PROMISE_END,
    XQC_HTTP3_HTTP_EVENT_MSG_END,
} xqc_http3_stream_http_event;

#if 0
typedef struct xqc_data_buf{

    xqc_list_head_t list_head;
    size_t data_len;
    char data[];
}xqc_data_buf_t;
#endif

typedef struct xqc_h3_data_buf{
    xqc_list_head_t list_head;
    size_t  buf_len;
    size_t  data_len;
    //size_t  data_left;
    size_t  already_consume;
    char    data[];
}xqc_h3_data_buf_t;

typedef xqc_h3_data_buf_t xqc_h3_frame_send_buf_t;
typedef xqc_h3_data_buf_t xqc_data_buf_t;

typedef struct xqc_h3_stream_s {
    xqc_stream_t        *stream;
    xqc_h3_conn_t       *h3_conn;
    xqc_h3_stream_type_t h3_stream_type;
    xqc_h3_request_t    *h3_request;
    void                *user_data;

    xqc_http3_stream_read_state read_state;
    xqc_http3_stream_type type;
    xqc_http3_stream_flag flags;

    xqc_http3_stream_http_state rx_http_state;
    xqc_http3_stream_http_state tx_http_state;

    xqc_list_head_t     send_header_data_buf;
    xqc_list_head_t     send_frame_data_buf;

    xqc_list_head_t     recv_header_data_buf;
    xqc_list_head_t     recv_body_data_buf;

} xqc_h3_stream_t;

extern const xqc_stream_callbacks_t stream_callbacks;

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream, xqc_h3_stream_type_t h3_stream_type, void *user_data);

void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream);

int
xqc_h3_stream_read_state_init(xqc_http3_stream_read_state * read_state);

int
xqc_h3_stream_create_control(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream);

ssize_t
xqc_h3_stream_send(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin);

ssize_t
xqc_h3_stream_send_header(xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers);

ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin);

ssize_t
xqc_h3_stream_recv_header(xqc_h3_stream_t *h3_stream);

ssize_t
xqc_h3_stream_recv_data(xqc_h3_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin);

#endif /* _XQC_H3_STREAM_H_INCLUDED_ */
