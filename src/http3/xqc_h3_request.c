
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"

xqc_h3_request_t *
xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, void *user_data)
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

    h3_conn = (xqc_h3_conn_t*)stream->stream_conn->app_proto_user_data;

    h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_TYPE_REQUEST, user_data);
    if (!h3_stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
        return NULL;
    }

    h3_request = xqc_h3_request_create_inner(h3_conn, h3_stream, user_data);
    if (!h3_request) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
        return NULL;
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3_stream->stream_id, h3_conn->conn, xqc_conn_state_2_str(h3_conn->conn->conn_state),
            xqc_conn_flag_2_str(h3_conn->conn->conn_flag));
    return h3_request;
}

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request)
{
    if (h3_request->request_if->h3_request_close_notify) {
        h3_request->request_if->h3_request_close_notify(h3_request, h3_request->user_data);
    }

    for (size_t i = 0; i < XQC_H3_REQUEST_MAX_HEADERS_CNT; i++) {
        xqc_h3_headers_free(&h3_request->h3_header[i]);
    }

    xqc_list_buf_list_free(&h3_request->body_buf);
    xqc_free(h3_request);
}

xqc_int_t 
xqc_h3_request_close(xqc_h3_request_t *h3_request)
{
    xqc_connection_t *conn = h3_request->h3_stream->h3c->conn;
    xqc_h3_stream_t *h3s = h3_request->h3_stream;

    xqc_int_t ret = xqc_h3_stream_close(h3_request->h3_stream);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|fail|ret:%d|stream_id:%ui|conn:%p|conn_state:%s|"
                "flag:%s|", ret, h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
                xqc_conn_flag_2_str(conn->conn_flag));
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn->conn_flag));

    return XQC_OK;
}

void
xqc_h3_request_header_initial(xqc_h3_request_t *h3_request)
{
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_HEADER]);
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_TRAILER_HEADER]);
}


xqc_int_t
xqc_h3_request_init_callbacks(xqc_h3_request_t *h3r)
{
    xqc_h3_callbacks_t *h3_cbs = NULL;
    xqc_int_t ret = xqc_h3_ctx_get_app_callbacks(&h3_cbs);
    if (XQC_OK != ret || h3_cbs == NULL) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|can't get app callbacks, not initialized ?");
        return ret;
    }

    h3r->request_if = &h3_cbs->h3r_cbs;

    return XQC_OK;
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
    h3_request->fin_flag = 0;
    xqc_h3_request_header_initial(h3_request);

    h3_stream->h3r = h3_request;

    xqc_init_list_head(&h3_request->body_buf);
    h3_request->body_buf_count = 0;

    xqc_h3_request_init_callbacks(h3_request);

    if (h3_request->request_if->h3_request_create_notify) {
        h3_request->request_if->h3_request_create_notify(h3_request, h3_request->user_data);
    }

    return h3_request;
}

xqc_request_stats_t
xqc_h3_request_get_stats(xqc_h3_request_t *h3_request)
{
    xqc_request_stats_t stats;
    uint64_t conn_err = h3_request->h3_stream->h3c->conn->conn_err;
    stats.recv_body_size = h3_request->body_recvd;
    stats.send_body_size = h3_request->body_sent;
    stats.recv_header_size = h3_request->header_recvd;
    stats.send_header_size = h3_request->header_sent;
    stats.stream_err = conn_err != 0 ? conn_err : (int)xqc_h3_stream_get_err(h3_request->h3_stream);
    return stats;
}

void
xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data)
{
    h3_request->user_data = user_data;
}


/**
 * HTTP/3 request send headers.
 * Put pesudo headers in the front of list.
 * @param headers       an array of headers
 * @param fin           headers only
 */
ssize_t
xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers, uint8_t fin)
{
    if (headers && !headers->headers && headers->count) {
        return -XQC_H3_EPARAM;
    }

    if (!headers || !headers->count) { //没有KV要发送。
        if (fin) { //只为发个FIN标记。
            return xqc_h3_request_send_body(h3_request, NULL, 0, 1);
        }

        xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR, "|headers MUST NOT be NULL or empty|");
        return -XQC_H3_EPARAM;
    }

    /*  malloc a new  move pesudo headers in the front of list */
    xqc_http_headers_t new_headers;
    xqc_http_headers_t *headers_in = &new_headers;
    headers_in->headers = xqc_malloc(headers->count * sizeof(xqc_http_header_t));
    if (headers_in->headers == NULL) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR, "|malloc error|");
        return -XQC_H3_EMALLOC;
    }

    headers_in->capacity = headers->count;
    headers_in->total_len = 0;

    /* make pesudo headers first */
    int i = 0, pt = 0;
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) == ':')
        {
            headers_in->headers[pt].name = headers->headers[i].name;
            headers_in->headers[pt].value = headers->headers[i].value;
            headers_in->headers[pt].flags = headers->headers[i].flags;
            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    /* copy other headers */
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) != ':')
        {
            headers_in->headers[pt].name = headers->headers[i].name;
            headers_in->headers[pt].value = headers->headers[i].value;
            headers_in->headers[pt].flags = headers->headers[i].flags;
            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    headers_in->count = pt;
    ssize_t sent = xqc_h3_stream_send_headers(h3_request->h3_stream, headers_in, fin);

    /* free headers_in->headers */
    xqc_free(headers_in->headers);

    return sent;
}


ssize_t
xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data, size_t data_size,
    uint8_t fin)
{
    /* data_size is allowed if it's fin only */
    if (data_size > 0 && data == NULL) {
        return -XQC_H3_EPARAM;
    }

    ssize_t sent = xqc_h3_stream_send_data(h3_request->h3_stream, data, data_size, fin);
    if (sent == -XQC_EAGAIN) {
        xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG,
                "|xqc_h3_stream_send_data eagain|stream_id:%ui|data_size:%z|fin:%d|",
                h3_request->h3_stream->stream_id, data_size, fin);
        return sent;

    } else if (sent < 0) {
        xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_ERROR,
                "|xqc_h3_stream_send_data error|stream_id:%ui|ret:%z|data_size:%z|fin:%d|",
                h3_request->h3_stream->stream_id, sent, data_size, fin);
        return sent;
    }

    h3_request->body_sent += sent;
    if (fin && sent == data_size) {
        h3_request->body_sent_final_size = h3_request->body_sent;
    }

    xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%z|sent:%z|"
            "body_sent:%uz|body_sent_final_size:%uz|fin:%d|conn:%p|",
            h3_request->h3_stream->stream_id, data_size, sent, h3_request->body_sent, 
            h3_request->body_sent_final_size, fin, h3_request->h3_stream->h3c->conn);

    return sent;
}


xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin)
{
    *fin = h3_request->fin_flag;

    /* header */
    if (h3_request->read_flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_DEBUG,
                "|recv header|stream_id:%ui|fin:%d|conn:%p|",
                h3_request->h3_stream->stream_id, *fin,
                h3_request->h3_stream->h3c->conn);

        /* set headers flag to NONE */
        h3_request->read_flag &= ~XQC_REQ_NOTIFY_READ_HEADER;
        return &h3_request->h3_header[XQC_H3_REQUEST_HEADER];
    }

    /* trailer header */
    if (h3_request->read_flag & XQC_REQ_NOTIFY_READ_TRAILER_HEADER) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_DEBUG,
                "|recv tailer header|stream_id:%ui|fin:%d|conn:%p|",
                h3_request->h3_stream->stream_id, *fin,
                h3_request->h3_stream->h3c->conn);

        /* set headers flag to NONE */
        h3_request->read_flag &= ~XQC_REQ_NOTIFY_READ_TRAILER_HEADER;
        return &h3_request->h3_header[XQC_H3_REQUEST_TRAILER_HEADER];
    }

    return NULL;
}

ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf,
    size_t recv_buf_size, uint8_t *fin)
{
    ssize_t n_recv = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_buf_t *list_buf = NULL;
    *fin = XQC_FALSE;

    xqc_list_for_each_safe(pos, next, &h3_request->body_buf) {
        list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = list_buf->buf;
        if (buf->data_len == 0) {
            h3_request->body_buf_count--;
            xqc_list_buf_free(list_buf);
            continue;
        }

        if (buf->data_len - buf->consumed_len <= recv_buf_size - n_recv) {
            memcpy(recv_buf + n_recv, buf->data + buf->consumed_len,
                   buf->data_len - buf->consumed_len);
            n_recv += buf->data_len - buf->consumed_len;
            h3_request->body_buf_count--;
            xqc_list_buf_free(list_buf);

        } else {
            memcpy(recv_buf + n_recv, buf->data + buf->consumed_len, recv_buf_size - n_recv);
            buf->consumed_len += recv_buf_size - n_recv;
            n_recv = recv_buf_size;
            break;
        }
    }

    h3_request->body_recvd += n_recv;
    if (h3_request->body_buf_count == 0) {
        *fin = h3_request->fin_flag;
        if (*fin) {
            h3_request->body_recvd_final_size = h3_request->body_recvd;
        }
    }

    if (n_recv == 0 && !*fin) {
        return -XQC_EAGAIN;
    }

    xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG,
            "|stream_id:%ui|recv_buf_size:%z|n_recv:%z|body_recvd:%uz|body_recvd_final_size:%uz|"
            "fin:%d|conn:%p|", h3_request->h3_stream->stream_id, recv_buf_size,
            n_recv, h3_request->body_recvd, h3_request->body_recvd_final_size, *fin,
            h3_request->h3_stream->h3c->conn);
    return n_recv;
}

xqc_int_t
xqc_h3_request_on_recv_header(xqc_h3_request_t *h3r)
{
    /* used to set read_flag */
    static const xqc_request_notify_flag_t hdr_type_2_flag[XQC_H3_REQUEST_MAX_HEADERS_CNT] = {
        XQC_REQ_NOTIFY_READ_HEADER,
        XQC_REQ_NOTIFY_READ_TRAILER_HEADER
    };

    xqc_http_headers_t *headers;

    /* header section and trailer header section are all processed */
    if (h3r->current_header >= XQC_H3_REQUEST_MAX_HEADERS_CNT) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_WARN, "|headers count exceed 2|"
                "stream_id:%ui|", h3r->h3_stream->stream_id);
        return -XQC_H3_INVALID_HEADER;
    }

    headers = &h3r->h3_header[h3r->current_header];

    /* header is too large */
    if (headers->total_len
        > h3r->h3_stream->h3c->local_h3_conn_settings.max_field_section_size)
    {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|large nv|conn:%p|fields_size:%ui|exceed|"
                "SETTINGS_MAX_FIELD_SECTION_SIZE:%ui|", h3r->h3_stream->h3c->conn,
                headers->total_len, 
                h3r->h3_stream->h3c->local_h3_conn_settings.max_field_section_size);
        return -XQC_H3_INVALID_HEADER;
    }

    /* set read flag */
    h3r->read_flag |= hdr_type_2_flag[h3r->current_header];

    h3r->header_recvd += headers->total_len;

    /* prepare to process next header */
    h3r->current_header++;

    /* header notify callback */
    xqc_int_t ret = h3r->request_if->h3_request_read_notify(h3r, h3r->read_flag, h3r->user_data);
    if (ret < 0) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                h3r->h3_stream->h3c->conn);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_request_on_recv_body(xqc_h3_request_t *h3r)
{
    /* there might be a fin only operation, which shall be notified to user */
    if (!xqc_list_empty(&h3r->body_buf) || (h3r->fin_flag == XQC_TRUE)) {
        xqc_request_notify_flag_t flag = 0;

        if (!xqc_list_empty(&h3r->body_buf)) {
            flag |= XQC_REQ_NOTIFY_READ_BODY;
        }

        xqc_int_t ret = h3r->request_if->h3_request_read_notify(h3r, flag, h3r->user_data);
        if (ret < 0) {
            xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                    "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                    h3r->h3_stream->h3c->conn);
            return ret;
        }
    }

    return XQC_OK;
}

void*
xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->h3c->user_data;
}

xqc_stream_id_t
xqc_h3_stream_id(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->stream_id;
}

xqc_http_headers_t *
xqc_h3_request_get_writing_headers(xqc_h3_request_t *h3r)
{
    if (h3r->current_header >= XQC_H3_REQUEST_MAX_HEADERS_CNT) {
        return NULL;
    }

    return &h3r->h3_header[h3r->current_header];
}
