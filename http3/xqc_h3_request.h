#ifndef _XQC_H3_REQUEST_H_INCLUDED_
#define _XQC_H3_REQUEST_H_INCLUDED_

#include "xqc_h3_stream.h"

typedef struct xqc_h3_request_s {
    xqc_h3_stream_t     *h3_stream;
    void                *user_data;
    xqc_h3_request_callbacks_t
                        *request_if;
    size_t              body_recvd;
    size_t              body_len;
    size_t              header_len;
} xqc_h3_request_t;

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request);

xqc_h3_request_t *
xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data);

#endif /* _XQC_H3_REQUEST_H_INCLUDED_ */
