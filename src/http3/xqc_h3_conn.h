#ifndef _XQC_H3_CONN_H_INCLUDED_
#define _XQC_H3_CONN_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_qpack.h"

#define XQC_H3_SETTINGS_UNSET XQC_MAX_UINT64_VALUE

typedef struct xqc_h3_conn_s xqc_h3_conn_t;
typedef struct xqc_h3_stream_s xqc_h3_stream_t;
typedef struct xqc_h3_context_s xqc_h3_context_t;

/* Send CONNECTION_CLOSE with err if ret is an h3 retcode */
#define XQC_H3_CONN_ERR(h3_conn, err, ret) do {                 \
    if (h3_conn->conn->conn_err == 0 && ret <= -XQC_H3_EMALLOC) {\
        h3_conn->conn->conn_err = err;                          \
        h3_conn->conn->conn_flag |= XQC_CONN_FLAG_ERROR;        \
        xqc_log(h3_conn->conn->log, XQC_LOG_ERROR, "|conn:%p|err:0x%xi|ret:%i|%s|", \
            h3_conn->conn, err, ret, xqc_conn_addr_str(h3_conn->conn)); \
    }                                                           \
} while(0)                                                      \

extern xqc_h3_conn_settings_t default_h3_conn_settings;

typedef enum {
    XQC_HTTP3_CONN_FLAG_SETTINGS_RECVED     = 1 << 0,
    XQC_HTTP3_CONN_FLAG_CONTROL_OPENED      = 1 << 1,
    XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST    = 1 << 2,
    XQC_HTTP3_CONN_FLAG_GOAWAY_SEND         = 1 << 3,
    XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD        = 1 << 4,
    XQC_HTTP3_CONN_FLAG_QPACK_ENCODER_OPENED = 1 << 5,
    XQC_HTTP3_CONN_FLAG_QPACK_DECODER_OPENED = 1 << 6,
    /* XQC_HTTP3_CONN_FLAG_MAX_PUSH_ID_QUEUED indicates that MAX_PUSH_ID
     *      has been queued to control stream. */
    //XQC_HTTP3_CONN_FLAG_MAX_PUSH_ID_QUEUED = 0x0010,
} xqc_http3_conn_flag;

struct xqc_h3_conn_s {
    xqc_connection_t           *conn;
    xqc_log_t                  *log;
    void                       *user_data;
    xqc_h3_stream_t            *control_stream_out;
    xqc_h3_stream_t            *control_stream_in;

    xqc_http3_conn_flag         flags;
    xqc_h3_conn_callbacks_t     h3_conn_callbacks;
    uint64_t                    max_stream_id_recvd;
    uint64_t                    goaway_stream_id;

    xqc_http3_qpack_decoder     qdec;
    xqc_http3_qpack_encoder     qenc;
    xqc_h3_stream_t            *qdec_stream;
    xqc_h3_stream_t            *qenc_stream;

    xqc_list_head_t             block_stream_head;

    xqc_h3_conn_settings_t      local_h3_conn_settings; //set by user for sending to the peer 
    xqc_h3_conn_settings_t      peer_h3_conn_settings;  //receive from peer
};

extern const xqc_conn_callbacks_t h3_conn_callbacks;

struct xqc_h3_context_s {
    uint64_t                    qpack_encoder_max_table_capacity;
    uint64_t                    qpack_decoder_max_table_capacity;
};


static inline void *
xqc_conn_get_user_data(xqc_connection_t *conn)
{
    if (conn->tlsref.alpn_num == XQC_ALPN_HTTP3_NUM) {
        return ((xqc_h3_conn_t*)conn->user_data)->user_data;
    } else {
        return conn->user_data;
    }
}

static inline xqc_http3_qpack_encoder * 
xqc_h3_conn_get_qpack_encoder(xqc_h3_conn_t *h3_conn)
{
    return &h3_conn->qenc;
}

xqc_h3_conn_t *
xqc_h3_conn_create(xqc_connection_t *conn, void *user_data);

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn);


xqc_h3_context_t * xqc_h3_context_create();
void xqc_h3_context_free(xqc_h3_context_t *ctx);


#endif /* _XQC_H3_CONN_H_INCLUDED_ */
