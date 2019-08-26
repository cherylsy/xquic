
#include "common/xqc_common.h"
#include "common/xqc_log.h"
#include "xqc_h3_stream.h"
#include "transport/xqc_stream.h"
#include "xqc_h3_conn.h"
#include "include/xquic.h"
#include "common/xqc_errno.h"
#include "xqc_h3_request.h"

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream, xqc_h3_stream_type_t h3_stream_type, void *user_data)
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
    h3_stream->user_data = user_data;

    stream->user_data = h3_stream;

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
        xqc_stream_type_t stream_type;
        if (h3_conn->conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            stream_type = XQC_CLI_UNI;
        } else {
            stream_type = XQC_SVR_UNI;
        }
        stream = xqc_create_stream_with_conn(h3_conn->conn, XQC_UNDEFINE_STREAM_ID, stream_type, NULL);
        if (!stream) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
            return -XQC_H3_ESTREAM;
        }
    }

    xqc_h3_stream_t *h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_CONTROL, NULL);
    if (!h3_stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
        return -XQC_H3_ESTREAM;
    }

    h3_conn->control_stream_out = h3_stream;

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}

ssize_t
xqc_h3_stream_send_header(xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers)
{
    ssize_t n_write = 0;
    //QPACK
    //gen HEADERS frame
    return n_write;
}

ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    ssize_t n_write = 0;
    //gen DATA frame
    n_write = xqc_stream_send(h3_stream->stream, data, data_size, fin);
    if (n_write < 0) {
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_send error|%z|", n_write);
    }
    return n_write;
}

ssize_t
xqc_h3_stream_recv_header(xqc_h3_stream_t *h3_stream)
{
    return 0;
}

ssize_t
xqc_h3_stream_recv_data(xqc_h3_stream_t *h3_stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin)
{
    //TODO: 从h3 stream的队列里读
    return xqc_stream_recv(h3_stream->stream, recv_buf, recv_buf_size, fin);
}

int
xqc_h3_stream_process_in(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    h3_stream->h3_stream_type = XQC_H3_STREAM_REQUEST;
    return XQC_OK;
}

int
xqc_h3_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    int ret;
    /* 服务端h3 stream可能还未创建 */
    if (!user_data) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|user_data empty|");
        return XQC_OK;
    }
    xqc_h3_stream_t *h3_stream = (xqc_h3_stream_t*)user_data;

    if (h3_stream->h3_stream_type == XQC_H3_STREAM_REQUEST) {
        ret = h3_stream->h3_request->request_if->h3_request_write_notify(h3_stream->h3_request,
                                                                         h3_stream->h3_request->user_data);
        if (ret) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|h3_request_write_notify error|%d|", ret);
            return ret;
        }
    }

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}

int
xqc_h3_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3_stream;
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)stream->stream_conn->user_data;
    int ret;

    /* 服务端h3 stream可能还未创建 */
    if (!user_data) {
        //parse h3 frame
        h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_NUM, NULL);
    } else {
        h3_stream = (xqc_h3_stream_t *) user_data;
    }

    unsigned char buff[1000] = {0};
    size_t buff_size = 1000;

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
            return read;
        }
        ret = xqc_h3_stream_process_in(h3_stream, buff, buff_size, fin);
        if (ret < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_in error|%d|", ret);
            return ret;
        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", read, fin);
    } while (read > 0 && !fin);

    if (h3_stream->h3_stream_type == XQC_H3_STREAM_REQUEST) {
        xqc_h3_request_t *h3_request;
        h3_request = h3_stream->h3_request;
        if (!h3_stream->h3_request) {
            h3_request = xqc_h3_request_create_2(h3_conn, h3_stream, NULL);
            if (!h3_request) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_request_create_2 error|");
                return -XQC_H3_EREQUEST;
            }
        }

        ret = h3_request->request_if->h3_request_read_notify(h3_request, h3_request->user_data);
        if (ret) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|", ret);
            return ret;
        }
    }
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}


int
xqc_h3_stream_close_notify(xqc_stream_t *stream, void *user_data)
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
        .stream_write_notify = xqc_h3_stream_write_notify,
        .stream_read_notify = xqc_h3_stream_read_notify,
        .stream_close = xqc_h3_stream_close_notify,
};