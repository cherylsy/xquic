#ifndef _XQC_H3_REQUEST_H_INCLUDED_
#define _XQC_H3_REQUEST_H_INCLUDED_

#include "xqc_h3_stream.h"

typedef struct xqc_h3_request_s {
    xqc_h3_stream_t     *h3_stream;
    void                *user_data;
} xqc_h3_request_t;

xqc_h3_request_t *
xqc_h3_request_create_2(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data);

#endif /* _XQC_H3_REQUEST_H_INCLUDED_ */
