#ifndef _XQC_H3_STREAM_H_INCLUDED_
#define _XQC_H3_STREAM_H_INCLUDED_

#include "include/xquic.h"
#include "include/xquic_typedef.h"
#include "xqc_h3_conn.h"

typedef enum {
    XQC_H3_STREAM_REQUEST,
    XQC_H3_STREAM_CONTROL,
    XQC_H3_STREAM_PUSH,
} xqc_h3_stream_type_t;

typedef struct xqc_h3_stream_s {
    xqc_stream_t        *stream;
    xqc_h3_conn_t       *h3_conn;
    xqc_h3_stream_type_t h3_stram_type;
} xqc_h3_stream_t;

extern const xqc_stream_callbacks_t stream_callbacks;

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_h3_stream_type_t h3_stream_type);

void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream);

int
xqc_stream_write_notify(xqc_stream_t *stream, void *user_data);

int
xqc_stream_read_notify(xqc_stream_t *stream, void *user_data);

int
xqc_stream_close_notify(xqc_stream_t *stream, void *user_data);

#endif /* _XQC_H3_STREAM_H_INCLUDED_ */
