
#include <transport/xqc_stream.h>
#include "xqc_h3_request.h"
#include "include/xquic.h"

xqc_h3_request_t*
xqc_h3_request_create(xqc_engine_t *engine,
                      xqc_cid_t *cid,
                      void *user_data)
{
    xqc_stream_t *stream;
    xqc_h3_stream_t *h3_stream;
    xqc_h3_request_t *h3_request;
    xqc_h3_conn_t *h3_conn;
    stream = xqc_stream_create(engine, cid, NULL);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_stream_create error|");
        return NULL;
    }

    h3_conn = (xqc_h3_conn_t*)stream->stream_conn->user_data;

    h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_REQUEST, user_data);
    if (!h3_stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
        return NULL;
    }

    h3_request = xqc_h3_request_create_inner(h3_conn, h3_stream, user_data);
    if (!h3_request) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
        return NULL;
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|success|");
    return h3_request;
}

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request)
{
    xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|");
    if (h3_request->request_if->h3_request_close) {
        h3_request->request_if->h3_request_close(h3_request, h3_request->user_data);
    }
    xqc_free(h3_request);
}

xqc_h3_request_t *
xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data)
{
    xqc_h3_request_t *h3_request;
    h3_request = xqc_calloc(1, sizeof(xqc_h3_request_t));
    if (!h3_request) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3_request->h3_stream = h3_stream;
    h3_request->user_data = user_data;
    h3_request->request_if = &h3_conn->conn->engine->eng_callback.h3_request_callbacks;

    h3_stream->h3_request = h3_request;

    if (h3_request->request_if->h3_request_create) {
        h3_request->request_if->h3_request_create(h3_request, h3_request->user_data);
    }
    return h3_request;
}

void
xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request,
                             void *user_data)
{
    h3_request->user_data = user_data;
}

ssize_t
xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers, uint8_t fin)
{
    return xqc_h3_stream_send_headers(h3_request->h3_stream, headers, fin);
}

ssize_t
xqc_h3_request_send_body(xqc_h3_request_t *h3_request,
                         unsigned char *data,
                         size_t data_size,
                         uint8_t fin)
{
    return xqc_h3_stream_send_data(h3_request->h3_stream, data, data_size, fin);
}

xqc_http_headers_t *
xqc_h3_request_recv_header(xqc_h3_request_t *h3_request, uint8_t *fin)
{
    return NULL;
}

ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin)
{
    ssize_t n_recv;
    n_recv = xqc_h3_stream_recv_data(h3_request->h3_stream, recv_buf, recv_buf_size, fin);
    if (n_recv < 0) {
        xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_ERROR,
                "|xqc_h3_stream_recv_data error|ret:%z|", n_recv);
        return n_recv;
    }

    h3_request->body_recvd += n_recv;
    if (*fin) {
        h3_request->body_len = h3_request->body_recvd;
    }
    xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG,
            "|body_recvd:%uz|body_len:%uz|n_recv:%z|",
            h3_request->body_recvd, h3_request->body_len, n_recv);
    return n_recv;
}