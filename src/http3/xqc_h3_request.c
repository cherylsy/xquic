
#include <xquic/xquic.h>
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_request.h"


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

    h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_HTTP3_STREAM_TYPE_REQUEST, user_data);
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
            stream->stream_id, h3_conn->conn, xqc_conn_state_2_str(h3_conn->conn->conn_state),
            xqc_conn_flag_2_str(h3_conn->conn->conn_flag));
    return h3_request;
}


int 
xqc_h3_headers_move_element(xqc_http_headers_t * dest, xqc_http_headers_t *src){

    size_t new_capacity = dest->count + src->count;
    if(dest->capacity < new_capacity){

        if(xqc_http_headers_realloc_buf(dest, new_capacity) < 0){
            return -XQC_QPACK_SAVE_HEADERS_ERROR;
        }
    }

    int i = 0;
    for(i = 0; i < src->count; i++){

        xqc_http_header_t * dest_header = & dest->headers[dest->count + i];
        xqc_http_header_t * src_header = & src->headers[i];
        dest_header->name = src_header->name;
        dest_header->value = src_header->value;
        dest_header->flags = src_header->flags;

        src_header->name.iov_base = NULL;
        src_header->value.iov_base = NULL;
    }

    return 0;
}


void 
xqc_h3_headers_free(xqc_http_headers_t *headers){

    int i = 0;
    xqc_http_header_t * header;

    if(headers->headers == NULL){
        return;
    }

    for(i = 0; i < headers->count; i++){
        header = & headers->headers[i];
        if(header->name.iov_base)
        {
            xqc_free(header->name.iov_base);
            header->name.iov_base = NULL;
        }
        if(header->value.iov_base)
        {
            xqc_free(header->value.iov_base);
            header->value.iov_base = NULL;
        }
    }

    xqc_free(headers->headers);
    headers->headers = NULL;
    headers->count = 0;
    headers->capacity = 0;
}


void 
xqc_h3_headers_initial(xqc_http_headers_t *headers)
{
    headers->headers = NULL;
    headers->count = 0;
    headers->capacity = 0;
}


void 
xqc_h3_request_header_free(xqc_h3_request_header_t * h3_header)
{
    int i = 0;
    for(i = 0; i < 2; i++){
        xqc_h3_headers_free(&h3_header->headers[i]);
    }
}


void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request)
{
    xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|");
    if (h3_request->request_if->h3_request_close_notify) {
        h3_request->request_if->h3_request_close_notify(h3_request, h3_request->user_data);
    }
    xqc_h3_request_header_free(&h3_request->h3_header);
    xqc_free(h3_request);
}


int 
xqc_h3_request_close (xqc_h3_request_t *h3_request)
{
    xqc_connection_t *conn = h3_request->h3_stream->h3_conn->conn;
    xqc_stream_t *stream = h3_request->h3_stream->stream;
    int ret = xqc_stream_close(stream);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|fail|ret:%d|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
                ret, stream->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
                xqc_conn_flag_2_str(conn->conn_flag));
        return ret;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            stream->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn->conn_flag));
    return XQC_OK;
}

void 
xqc_h3_request_header_initial(xqc_h3_request_header_t * h3_header)
{
    int i = 0;
    h3_header->read_flag = XQC_H3_REQUEST_HEADER_DATA_NONE;
    h3_header->writing_cursor = 0;

    for(i = 0; i < 2; i++){
        xqc_h3_headers_initial(&h3_header->headers[i]);
    }
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
    h3_request->flag = 0;
    xqc_h3_request_header_initial(&h3_request->h3_header);

    h3_stream->h3_request = h3_request;


    if (h3_request->request_if->h3_request_create_notify) {
        h3_request->request_if->h3_request_create_notify(h3_request, h3_request->user_data);
    }
    return h3_request;
}

xqc_request_stats_t
xqc_h3_request_get_stats(xqc_h3_request_t *h3_request)
{
    xqc_request_stats_t stats;
    uint64_t conn_err = h3_request->h3_stream->stream->stream_conn->conn_err;
    stats.recv_body_size = h3_request->body_recvd;
    stats.send_body_size = h3_request->body_sent;
    stats.recv_header_size = h3_request->h3_stream->header_recvd;
    stats.send_header_size = h3_request->h3_stream->header_sent;
    stats.stream_err = conn_err != 0 ? conn_err : h3_request->h3_stream->stream->stream_err;
    return stats;
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
    if (!headers) {
        return -XQC_H3_EPARAM;
    }
    return xqc_h3_stream_send_headers(h3_request->h3_stream, headers, fin);
}

ssize_t
xqc_h3_request_send_body(xqc_h3_request_t *h3_request,
                         unsigned char *data,
                         size_t data_size,
                         uint8_t fin)
{
    if (data_size > 0 && data == NULL) {
        return -XQC_H3_EPARAM;
    }
    ssize_t sent;
    sent = xqc_h3_stream_send_data(h3_request->h3_stream, data, data_size, fin);
    if (sent == -XQC_EAGAIN) {
        xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG,
                "|xqc_h3_stream_send_data eagain|stream_id:%ui|data_size:%z|fin:%d|",
                h3_request->h3_stream->stream->stream_id, data_size, fin);
        return sent;
    } else if (sent < 0) {
        xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_ERROR,
                "|xqc_h3_stream_send_data error|stream_id:%ui|ret:%z|data_size:%z|fin:%d|",
                h3_request->h3_stream->stream->stream_id, sent, data_size, fin);
        return sent;
    }

    h3_request->body_sent += sent;
    if (fin && sent == data_size) {
        h3_request->body_sent_final_size = h3_request->body_sent;
    }
    xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG,
            "|stream_id:%ui|data_size:%z|sent:%z|body_sent:%uz|body_sent_final_size:%uz|fin:%d|flag:%d|conn:%p|",
            h3_request->h3_stream->stream->stream_id,
            data_size, sent, h3_request->body_sent, h3_request->body_sent_final_size, fin,
            h3_request->h3_stream->stream->stream_flag, h3_request->h3_stream->h3_conn->conn);
    return sent;
}


xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin)
{
    *fin = 0;
    if(h3_request->flag & XQC_H3_REQUEST_HEADER_FIN){
        *fin = 1;
    }
    if(h3_request->h3_header.read_flag != XQC_H3_REQUEST_HEADER_DATA_NONE ){
        xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG,
                "|stream_id:%ui|fin:%d|flag:%d|conn:%p|",
                h3_request->h3_stream->stream->stream_id, *fin,
                h3_request->h3_stream->stream->stream_flag, h3_request->h3_stream->h3_conn->conn);
        uint8_t read_cursor = h3_request->h3_header.read_flag - 1;
        h3_request->h3_header.read_flag = XQC_H3_REQUEST_HEADER_DATA_NONE;
        //need set headers flag
        return &h3_request->h3_header.headers[read_cursor];
    }
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
                "|xqc_h3_stream_recv_data error|stream_id:%ui|ret:%z|conn:%p|",
                h3_request->h3_stream->stream->stream_id, n_recv, h3_request->h3_stream->h3_conn->conn);
        return n_recv;
    }

    h3_request->body_recvd += n_recv;
    if (*fin) {
        h3_request->body_recvd_final_size = h3_request->body_recvd;
    }
    xqc_log(h3_request->h3_stream->h3_conn->log, XQC_LOG_DEBUG,
            "|stream_id:%ui|recv_buf_size:%z|n_recv:%z|body_recvd:%uz|body_recvd_final_size:%uz|fin:%d|flag:%d|conn:%p|",
            h3_request->h3_stream->stream->stream_id,
            recv_buf_size, n_recv, h3_request->body_recvd, h3_request->body_recvd_final_size, *fin,
            h3_request->h3_stream->stream->stream_flag, h3_request->h3_stream->h3_conn->conn);
    return n_recv;
}


int 
xqc_h3_request_header_notify_read(xqc_h3_request_header_t * h3_header){

    if(h3_header->read_flag == XQC_H3_REQUEST_HEADER_DATA_NONE){
        h3_header->read_flag = 1 << h3_header->writing_cursor ;
        h3_header->writing_cursor = (h3_header->writing_cursor + 1)&XQC_H3_REQUEST_HEADER_MASK;
        //clear
    }else{

        if(h3_header->read_flag == 1 << h3_header->writing_cursor){
            //impossible
            return -1;
        }
        xqc_http_headers_t * src_headers = &h3_header->headers[h3_header->writing_cursor];
        xqc_http_headers_t * dest_headers = &h3_header->headers[(h3_header->writing_cursor + 1) & XQC_H3_REQUEST_HEADER_MASK];
        int ret = xqc_h3_headers_move_element( dest_headers, src_headers);
        if(ret < 0){
            return ret;
        }
    }

    /* should clear write header */
    xqc_h3_headers_free(&h3_header->headers[h3_header->writing_cursor]);

    return 0;

}


xqc_stream_id_t
xqc_h3_stream_id(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->stream->stream_id;
}


void*
xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->h3_conn->user_data;
}


