#ifndef _XQC_H3_REQUEST_H_INCLUDED_
#define _XQC_H3_REQUEST_H_INCLUDED_

#include "xqc_h3_stream.h"

typedef enum{
    XQC_H3_REQUEST_HEADER_COMPLETE_RECV = 1 << 0,
    XQC_H3_REQUEST_HEADER_ALREADY_READ  = 1 << 1,
    XQC_H3_REQUEST_HEADER_FIN           = 1 << 2,
    XQC_H3_REQUEST_HEADER_CAN_READ      = 1 << 3,
    XQC_H3_REQUEST_BODY_CAN_READ        = 1 << 4,
}xqc_h3_request_flag;

typedef struct xqc_h3_request_s {
    xqc_h3_stream_t     *h3_stream;
    void                *user_data;
    xqc_http_headers_t  headers;
    xqc_h3_request_flag flag;

    xqc_h3_request_callbacks_t
                        *request_if;
    size_t              body_recvd;
    size_t              body_recvd_final_size;
    size_t              body_sent;
    size_t              body_sent_final_size;
} xqc_h3_request_t;

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request);

xqc_h3_request_t *
xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data);

#endif /* _XQC_H3_REQUEST_H_INCLUDED_ */
