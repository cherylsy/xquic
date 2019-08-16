
#include "common/xqc_common.h"
#include "common/xqc_log.h"
#include "xqc_h3_stream.h"
#include "transport/xqc_stream.h"
#include "xqc_h3_conn.h"
#include "include/xquic.h"
#include "common/xqc_errno.h"

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream, xqc_h3_stream_type_t h3_stream_type)
{
    xqc_h3_stream_t *h3_stream;

    h3_stream = xqc_calloc(1, sizeof(xqc_h3_stream_t));
    if (!h3_stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3_stream->stream = stream;
    h3_stream->h3_conn = h3_conn;
    h3_stream->h3_stream_type = h3_stream_type;

    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;

    return h3_stream;
}

void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream)
{
    xqc_free(h3_stream);
}

int
xqc_h3_stream_create_control(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream)
{
    if (!stream) {
        stream = xqc_create_stream_with_conn(h3_conn->conn, 0, XQC_CLI_UNI, NULL);
        if (!stream) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
            return -XQC_H3_ESTREAM;
        }
    }

    xqc_h3_stream_t *h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_CONTROL);
    if (!h3_stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
        return -XQC_H3_ESTREAM;
    }

    stream->user_data = h3_stream;

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}


int
xqc_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    /* 服务端h3 stream可能还未创建 */
    if (!user_data) {
        return XQC_OK;
    }
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}

int
xqc_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    /* 服务端h3 stream可能还未创建 */
    if (!user_data) {
        return XQC_OK;
    }
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}


int
xqc_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    if (!(stream->stream_flag & XQC_STREAM_FLAG_HAS_H3)) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|has no h3 stream|");
        return XQC_OK;
    }
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;
    xqc_h3_stream_destroy(h3_stream);
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|destroy h3 stream success|");
    return XQC_OK;
}

const xqc_stream_callbacks_t stream_callbacks = {
        .stream_write_notify = xqc_stream_write_notify,
        .stream_read_notify = xqc_stream_read_notify,
        .stream_close = xqc_stream_close_notify,
};