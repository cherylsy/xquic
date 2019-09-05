#ifndef _XQC_H3_CONN_H_INCLUDED_
#define _XQC_H3_CONN_H_INCLUDED_

#include "include/xquic_typedef.h"
#include "transport/xqc_conn.h"
#include "xqc_h3_stream.h"

typedef struct xqc_h3_conn_s xqc_h3_conn_t;
typedef struct xqc_h3_stream_s xqc_h3_stream_t;


typedef enum {
    XQC_HTTP3_CONN_FLAG_SETTINGS_RECVED     = 1 << 0,
    XQC_HTTP3_CONN_FLAG_CONTROL_OPENED      = 1 << 1,
    XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST    = 1 << 2,
    XQC_HTTP3_CONN_FLAG_GOAWAY_SEND         = 1 << 3,
    XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD        = 1 << 4,
    //XQC_HTTP3_CONN_FLAG_QPACK_ENCODER_OPENED = 0x0004,
    //XQC_HTTP3_CONN_FLAG_QPACK_DECODER_OPENED = 0x0008,
    /* XQC_HTTP3_CONN_FLAG_MAX_PUSH_ID_QUEUED indicates that MAX_PUSH_ID
     *      has been queued to control stream. */
    //XQC_HTTP3_CONN_FLAG_MAX_PUSH_ID_QUEUED = 0x0010,
} xqc_http3_conn_flag;

struct xqc_h3_conn_s {
    xqc_connection_t        *conn;
    xqc_log_t               *log;
    void                    *user_data;
    xqc_h3_stream_t         *control_stream_out;
    xqc_h3_stream_t         *control_stream_in;

    xqc_http3_conn_flag     flags;
    xqc_h3_conn_callbacks_t h3_conn_callbacks;
    uint64_t                max_stream_id_recvd;
    uint64_t                goaway_stream_id;
};


extern const xqc_conn_callbacks_t conn_callbacks;

static inline void *
xqc_conn_get_user_data(xqc_connection_t *conn)
{
    if (conn->conn_settings.h3) {
        return ((xqc_h3_conn_t*)conn->user_data)->user_data;
    } else {
        return conn->user_data;
    }
}

xqc_h3_conn_t *
xqc_h3_conn_create(xqc_connection_t *conn, void *user_data);

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn);

int
xqc_h3_conn_create_notify(xqc_connection_t *conn, void *user_data);

int
xqc_h3_conn_close_notify(xqc_connection_t *conn, void *user_data);

#endif /* _XQC_H3_CONN_H_INCLUDED_ */
