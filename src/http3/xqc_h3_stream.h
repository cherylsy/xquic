#ifndef _XQC_H3_STREAM_H_INCLUDED_
#define _XQC_H3_STREAM_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_frame.h"
#include "src/http3/xqc_h3_qpack.h"

#if 0
typedef enum {
    XQC_H3_STREAM_REQUEST,
    XQC_H3_STREAM_CONTROL,
    XQC_H3_STREAM_PUSH,
    XQC_H3_STREAM_NUM,
} xqc_h3_stream_type_t;
#endif

typedef struct xqc_h3_conn_s xqc_h3_conn_t;
typedef struct xqc_h3_stream_s xqc_h3_stream_t;

/* xqc_http3_stream_type is unidirectional stream type. */
typedef enum {
    XQC_HTTP3_STREAM_TYPE_CONTROL = 0x00,
    XQC_HTTP3_STREAM_TYPE_PUSH = 0x01,
    XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER = 0x02,
    XQC_HTTP3_STREAM_TYPE_QPACK_DECODER = 0x03,
    XQC_HTTP3_STREAM_TYPE_REQUEST       = 0x10,
    XQC_HTTP3_STREAM_TYPE_UNKNOWN = 0xFF,
}xqc_h3_stream_type;


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
    XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY = 0x0400,
} xqc_http3_stream_flag;


typedef enum {
    XQC_HTTP3_HTTP_STATE_NONE,
    XQC_HTTP3_HTTP_STATE_BEGIN,
    XQC_HTTP3_HTTP_STATE_HEADERS,
    XQC_HTTP3_HTTP_STATE_DATA,
    XQC_HTTP3_HTTP_STATE_TRAILERS,
    XQC_HTTP3_HTTP_STATE_END,
} xqc_http3_stream_http_state;

typedef enum {
    XQC_HTTP3_HTTP_EVENT_DATA,
    XQC_HTTP3_HTTP_EVENT_HEADERS,
    XQC_HTTP3_HTTP_EVENT_MSG_END,
} xqc_http3_stream_http_event;


typedef enum {
    XQC_HTTP3_NO_FIN    = 0x00,
    XQC_HTTP3_STREAM_FIN = 0x01,
    XQC_HTTP3_FRAME_FIN = 0x02,
}xqc_h3_data_buf_fin_flag_t;

typedef struct xqc_h3_stream_s {
    xqc_stream_t                   *stream;
    xqc_h3_conn_t                  *h3_conn;
    xqc_h3_stream_type              h3_stream_type;
    xqc_h3_request_t               *h3_request;
    void                           *user_data;

    xqc_http3_stream_read_state     read_state;
    xqc_http3_stream_flag           flags;

    xqc_http3_stream_http_state     rx_http_state;
    xqc_http3_stream_http_state     tx_http_state;

    xqc_list_head_t                 send_frame_data_buf;
    uint64_t                        send_buf_count;

    xqc_list_head_t                 recv_data_buf;
    xqc_list_head_t                 recv_body_data_buf;
    xqc_http3_qpack_stream_context  qpack_sctx;

    xqc_list_head_t                 unack_block_list;

    uint32_t                        header_sent; //compressed header size
    uint32_t                        header_recvd; //compressed header size

} xqc_h3_stream_t;

extern const xqc_stream_callbacks_t h3_stream_callbacks;

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream, xqc_h3_stream_type h3_stream_type, void *user_data);

void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream);

int
xqc_h3_stream_read_state_init(xqc_http3_stream_read_state * read_state);

int
xqc_h3_stream_create_control_stream(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream);

ssize_t
xqc_h3_stream_send(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin);

ssize_t
xqc_h3_stream_send_headers(xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers, uint8_t fin);

ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin);

ssize_t
xqc_h3_stream_recv_data(xqc_h3_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin);

int xqc_h3_stream_create_qpack_stream(xqc_h3_conn_t *h3_conn, xqc_stream_t * stream, xqc_h3_stream_type stream_type);
#endif /* _XQC_H3_STREAM_H_INCLUDED_ */
