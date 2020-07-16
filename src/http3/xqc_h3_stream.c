
#include <xquic/xquic.h>
#include "src/common/xqc_common.h"
#include "src/common/xqc_log.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"


xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream, xqc_h3_stream_type h3_stream_type, void *user_data)
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

    memset(&(h3_stream->read_state), 0, sizeof(xqc_http3_stream_read_state));

    h3_stream->flags = XQC_HTTP3_STREAM_FLAG_NONE;
    h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_NONE;
    h3_stream->tx_http_state = XQC_HTTP3_HTTP_STATE_NONE;

    xqc_init_list_head(&h3_stream->send_frame_data_buf);
    h3_stream->send_buf_count = 0;

    xqc_init_list_head(&h3_stream->recv_data_buf);
    xqc_init_list_head(&h3_stream->recv_body_data_buf);

    xqc_http3_qpack_stream_context_init(&h3_stream->qpack_sctx, stream->stream_id);
    xqc_init_list_head(&h3_stream->unack_block_list);

    stream->user_data = h3_stream;

    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;

    return h3_stream;
}


void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream->h3_request) {
        xqc_h3_request_destroy(h3_stream->h3_request);
    }
    xqc_http3_qpack_stream_context_free(&h3_stream->qpack_sctx);
    xqc_h3_stream_free_data_buf(h3_stream);

    xqc_http3_stream_clear_unack_and_block_stream_list(h3_stream);

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|",
            h3_stream->stream->stream_id, h3_stream->h3_stream_type);
    xqc_free(h3_stream);
}


int
xqc_h3_stream_create_control_stream(xqc_h3_conn_t *h3_conn, xqc_stream_t *stream)
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
            return -XQC_ECREATE_STREAM;
        }
    }

    xqc_h3_stream_t *h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_HTTP3_STREAM_TYPE_CONTROL, NULL);
    if (!h3_stream) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
        return -XQC_H3_ECREATE_STREAM;
    }

    h3_conn->control_stream_out = h3_stream;

    if (xqc_h3_uni_stream_write_stream_type(h3_stream, XQC_HTTP3_STREAM_TYPE_CONTROL) != XQC_OK) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_uni_stream_write_stream_type error|");
        return -XQC_H3_ECREATE_STREAM;
    }
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|", stream->stream_id);

    return XQC_OK;
}


int 
xqc_h3_stream_create_qpack_stream(xqc_h3_conn_t *h3_conn, xqc_stream_t * stream, 
    xqc_h3_stream_type stream_type)
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
            return -XQC_H3_ECREATE_STREAM;
        }
    }

    xqc_h3_stream_t *h3_stream = xqc_h3_stream_create(h3_conn, stream, stream_type, NULL);

    if(stream_type == XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER){
        h3_conn->qenc_stream = h3_stream;
    }else if(stream_type == XQC_HTTP3_STREAM_TYPE_QPACK_DECODER){
        h3_conn->qdec_stream = h3_stream;
    }else{
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_create_qpack_stream error|");
        return -XQC_H3_ECREATE_STREAM;
    }

    if (xqc_h3_uni_stream_write_stream_type(h3_stream, stream_type) != XQC_OK) {
        return -XQC_H3_ECREATE_STREAM;
    }
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|stream_type:%d|", stream->stream_id, stream_type);

    return XQC_OK;
}


ssize_t
xqc_h3_stream_send(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;
    if (h3_stream->h3_stream_type == XQC_HTTP3_STREAM_TYPE_REQUEST &&
        (h3_conn->flags & XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD) &&
        h3_stream->stream->stream_id >= h3_conn->goaway_stream_id) {

        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|goaway recvd, stop send|");
        return -XQC_H3_EGOAWAY_RECVD;
    }
    ssize_t n_write = 0;
    n_write = xqc_stream_send(h3_stream->stream, data, data_size, fin);
    if (n_write < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_send error|%z|", n_write);
        XQC_H3_CONN_ERR(h3_conn, HTTP_INTERNAL_ERROR, n_write);
    }
    xqc_engine_main_logic_internal(h3_stream->h3_conn->conn->engine, h3_stream->h3_conn->conn);
    return n_write;
}


ssize_t
xqc_h3_stream_send_headers(xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers, uint8_t fin)
{
    ssize_t  n_write = 0;
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;
    h3_stream->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    //QPACK
    //gen HEADERS frame
    n_write = xqc_http3_write_headers(h3_conn, h3_stream, headers, fin);
    if(n_write < 0){
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|n_write:%z error|stream_id:%ui|", n_write, h3_stream->stream->stream_id);
        XQC_H3_CONN_ERR(h3_conn, HTTP_INTERNAL_ERROR, n_write);
    }
    h3_stream->header_sent += n_write;
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|n_write:%z|stream_id:%ui|fin:%d|conn:%p|flag:%s|",
            n_write, h3_stream->stream->stream_id, fin, h3_conn->conn, xqc_conn_flag_2_str(h3_conn->conn->conn_flag));
    h3_stream->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    xqc_engine_main_logic_internal(h3_conn->conn->engine, h3_conn->conn);
    return n_write;
}


ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    ssize_t n_write = 0;

    h3_stream->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    n_write = xqc_http3_write_frame_data(h3_stream, data, data_size, fin);
    if (n_write == -XQC_EAGAIN) {
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|xqc_http3_write_frame_data eagain|stream_id:%ui|data_size:%uz|fin:%d|",
                h3_stream->stream->stream_id, data_size, fin);
        return n_write;
    } else if (n_write < 0) {
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_write_frame_data error|%z|stream_id:%ui|data_size:%uz|fin:%d|",
                h3_stream->stream->stream_id, n_write, data_size, fin);
        XQC_H3_CONN_ERR(h3_stream->h3_conn, HTTP_INTERNAL_ERROR, n_write);
    }
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%uz|n_write:%z|fin:%d|conn:%p|",
            h3_stream->stream->stream_id, data_size, n_write, fin, h3_stream->h3_conn->conn);
    if (n_write == data_size) {
        h3_stream->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    }
    xqc_engine_main_logic_internal(h3_stream->h3_conn->conn->engine, h3_stream->h3_conn->conn);
    return n_write;
}

ssize_t
xqc_h3_stream_recv_data(xqc_h3_stream_t *h3_stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin)
{

    xqc_list_head_t *pos, *next;
    xqc_h3_data_buf_t *h3_data_buf;
    size_t recv_buf_left = recv_buf_size;
    size_t h3_data_buf_left;
    size_t n_recved = 0;
    xqc_list_for_each_safe(pos, next, &h3_stream->recv_body_data_buf) {
        h3_data_buf = xqc_list_entry(pos, xqc_h3_data_buf_t, list_head);
        h3_data_buf_left = h3_data_buf->data_len - h3_data_buf->already_consume;
        if (recv_buf_left < h3_data_buf_left) {
            memcpy(recv_buf + n_recved, h3_data_buf->data + h3_data_buf->already_consume, recv_buf_left);
            n_recved += recv_buf_left;
            h3_data_buf->already_consume += recv_buf_left;
            recv_buf_left = 0;
            break;
        } else {
            memcpy(recv_buf + n_recved, h3_data_buf->data + h3_data_buf->already_consume, h3_data_buf_left);
            n_recved += h3_data_buf_left;
            h3_data_buf->already_consume += h3_data_buf_left;
            recv_buf_left -= h3_data_buf_left;
            if (h3_data_buf->fin_flag & XQC_HTTP3_STREAM_FIN) {
                *fin = 1;
            }
            xqc_list_del_init(pos);
            xqc_free(h3_data_buf);
            if (0 == recv_buf_left) {
                break;
            }
        }
    }
    return (n_recved == 0 && *fin == 0) ? -XQC_EAGAIN : n_recved;
}

int
xqc_h3_stream_process_in(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    ssize_t processed = 0;
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|data_size:%z|",
            h3_stream->stream->stream_id, h3_stream->h3_stream_type, data_size);
    if (XQC_HTTP3_STREAM_TYPE_UNKNOWN == h3_stream->h3_stream_type) {
        if (h3_stream->stream->stream_type == XQC_SVR_BID || h3_stream->stream->stream_type == XQC_CLI_BID) {
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_REQUEST;
            if (!h3_stream->h3_request) {
                h3_stream->h3_request = xqc_h3_request_create_inner(h3_conn, h3_stream, NULL);
                if (!h3_stream->h3_request) {
                    xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
                    return -XQC_H3_ECREATE_REQUEST;
                }
            }
        }
        /*else {
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_CONTROL;
            h3_conn->control_stream_in = h3_stream;
        }*/
    }

    if(h3_stream->stream->stream_type == XQC_CLI_UNI || h3_stream->stream->stream_type == XQC_SVR_UNI){

        processed = xqc_http3_conn_read_uni(h3_conn, h3_stream, data, data_size, fin);
        if(processed < 0 || processed != data_size) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_uni error|%z|", processed);
            XQC_H3_CONN_ERR(h3_conn, HTTP_FRAME_ERROR, -XQC_H3_EPROC_CONTROL);
            return -XQC_H3_EPROC_CONTROL;

        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_http3_conn_read_uni|%z|", processed);
    }else if (XQC_HTTP3_STREAM_TYPE_REQUEST == h3_stream->h3_stream_type) {
        processed = xqc_http3_conn_read_bidi(h3_conn, h3_stream, data, data_size, fin);
        if (processed < 0) { //process error
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error|%z|", processed);
            XQC_H3_CONN_ERR(h3_conn, HTTP_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
            return -XQC_H3_EPROC_REQUEST;
        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_http3_conn_read_bidi|%z|", processed);

        if(processed < data_size){
            if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){
                int rv = xqc_buf_to_tail(&h3_stream->recv_data_buf, data + processed, data_size - processed, fin);
                if(rv < 0){
                    return rv;
                }
                return XQC_OK;
            }else{
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error, read data not completely");
                XQC_H3_CONN_ERR(h3_conn, HTTP_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
                return -XQC_H3_EPROC_REQUEST;
            }

        }

    }
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

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|stream_type:%d|stream_id:%ui|conn:%p|",
            h3_stream->h3_stream_type, h3_stream->stream->stream_id, stream->stream_conn);

    ret = xqc_h3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf);
    if (ret < 0) {
        if (ret == -XQC_EAGAIN) {
            return XQC_OK;
        } else {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_h3_send_frame_buffer error|%d|", ret);
            return ret;
        }
    }

    if (h3_stream->h3_stream_type == XQC_HTTP3_STREAM_TYPE_REQUEST && (h3_stream->flags & XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY)) {
        ret = h3_stream->h3_request->request_if->h3_request_write_notify(h3_stream->h3_request,
                                                                         h3_stream->h3_request->user_data);
        if (ret < 0) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|h3_request_write_notify error|%d|", ret);
            return ret;
        }
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|h3_request_write_notify|success|");
    }

    return XQC_OK;
}

#define XQC_SIZE_4K (4096)
int
xqc_h3_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3_stream;
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)stream->stream_conn->user_data;
    int ret;

    /* 服务端h3 stream可能还未创建 */
    if (!user_data) {
        h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_HTTP3_STREAM_TYPE_UNKNOWN, NULL);
        if (!h3_stream) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
            return -XQC_H3_ECREATE_STREAM;
        }

    } else {
        h3_stream = (xqc_h3_stream_t *) user_data;
    }

    if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD && stream->stream_id >= h3_conn->goaway_stream_id) {
        //send stop_sending
        return xqc_write_stop_sending_to_packet(h3_conn->conn, stream, HTTP_REQUEST_CANCELLED);
    }


    ssize_t read;
    unsigned char fin;
    size_t buff_size = 0;
    do {
        if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){

            char * buff = NULL;
            buff_size = 0;
            xqc_list_head_t * head = &h3_stream->recv_data_buf;
            xqc_data_buf_t * data_buf = NULL;
            if(!xqc_list_empty(head)){

                xqc_list_head_t * ptr = head->prev;
                xqc_data_buf_t * data_buf = xqc_list_entry(ptr, xqc_data_buf_t, list_head);
                if(data_buf->data_len < data_buf->buf_len){
                    buff = data_buf->data + data_buf->data_len;
                    buff_size = data_buf->buf_len - data_buf->data_len;
                }else{
                    data_buf = xqc_create_data_buf(XQC_SIZE_4K, 0);
                    xqc_list_add_tail(&data_buf->list_head, head);
                }
            }else{
                data_buf = xqc_create_data_buf(XQC_SIZE_4K, 0);
                xqc_list_add_tail(&data_buf->list_head, head);
            }
            buff = data_buf->data + data_buf->data_len;
            buff_size = data_buf->buf_len - data_buf->data_len;

            read = xqc_stream_recv(stream, buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;
            } else if (read < 0) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
                return XQC_OK;
            }
            xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", read, fin);

            data_buf->data_len += read;
            data_buf->fin_flag = fin;
        }else{
            unsigned char buff[XQC_SIZE_4K] = {0};
            buff_size = XQC_SIZE_4K;
            read = xqc_stream_recv(stream, buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;
            } else if (read < 0) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
                return XQC_OK;
            }
            xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", read, fin);

            ret = xqc_h3_stream_process_in(h3_stream, buff, read, fin);
            if (ret < 0) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_in error|%d|", ret);
                XQC_H3_CONN_ERR(h3_conn, HTTP_INTERNAL_ERROR, ret);
                return ret;
            }

        }
    } while (read == buff_size && !fin);

    xqc_h3_request_t *h3_request;
    h3_request = h3_stream->h3_request;

    if (h3_stream->h3_stream_type == XQC_HTTP3_STREAM_TYPE_REQUEST && ((h3_request->h3_header.read_flag != XQC_H3_REQUEST_HEADER_DATA_NONE) || !xqc_list_empty(&h3_stream->recv_body_data_buf))) {
        xqc_request_notify_flag_t flag = 0;
        if (h3_request->h3_header.read_flag != XQC_H3_REQUEST_HEADER_DATA_NONE) {
            flag |= XQC_REQ_NOTIFY_READ_HEADER;
        }
        if (!xqc_list_empty(&h3_stream->recv_body_data_buf)) {
            flag |= XQC_REQ_NOTIFY_READ_BODY;
        }
        if (flag == 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|notify_flag empty|");
            return -XQC_H3_EPARAM;
        }
        ret = h3_request->request_if->h3_request_read_notify(h3_request, h3_request->user_data, flag);
        if (ret < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|stream_id:%ui|conn:%p|",
                    ret, h3_stream->stream->stream_id, h3_conn->conn);
            return ret;
        }
    }
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|", h3_stream->stream->stream_id, h3_conn->conn);
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

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|destroy h3 stream success|h3_stream_type:%d|",
            h3_stream->h3_stream_type);

    xqc_h3_stream_destroy(h3_stream);
    return XQC_OK;
}

const xqc_stream_callbacks_t h3_stream_callbacks = {
        .stream_write_notify = xqc_h3_stream_write_notify,
        .stream_read_notify = xqc_h3_stream_read_notify,
        .stream_close_notify = xqc_h3_stream_close_notify,
};
