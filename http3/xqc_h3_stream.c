
#include "common/xqc_common.h"
#include "common/xqc_log.h"
#include "xqc_h3_stream.h"
#include "transport/xqc_stream.h"
#include "xqc_h3_conn.h"
#include "include/xquic.h"
#include "common/xqc_errno.h"

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_h3_stream_type_t h3_stream_type)
{
    xqc_h3_stream_t *h3_stream;
    xqc_stream_t *stream;

    h3_stream = xqc_calloc(1, sizeof(xqc_h3_stream_t));
    if (!h3_stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    stream = xqc_create_stream_with_conn(h3_conn->conn, (void*)h3_stream);
    if (!stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
        xqc_h3_stream_destroy(h3_stream);
        return NULL;
    }

    h3_stream->stream = stream;
    h3_stream->h3_conn = h3_conn;
    h3_stream->h3_stram_type = h3_stream_type;

    return h3_stream;
}

void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream)
{
    xqc_destroy_stream(h3_stream->stream);
    xqc_free(h3_stream);
}

int
xqc_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;

    return XQC_OK;
}

int
xqc_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;
    return XQC_OK;
}

int
xqc_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;
    return XQC_OK;
}

const xqc_stream_callbacks_t stream_callbacks = {
        .stream_write_notify = xqc_stream_write_notify,
        .stream_read_notify = xqc_stream_read_notify,
        .stream_close = xqc_stream_close_notify,
};