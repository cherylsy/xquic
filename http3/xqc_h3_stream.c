
#include "common/xqc_common.h"
#include "common/xqc_log.h"
#include "xqc_h3_stream.h"
#include "transport/xqc_stream.h"
#include "xqc_h3_conn.h"
#include "include/xquic.h"
#include "common/xqc_errno.h"
#include "xqc_h3_request.h"


int xqc_http3_stream_link_tnode(xqc_h3_stream_t * h3_stream){
#ifdef XQC_HTTP3_PRIORITY_ENABLE
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;
    xqc_h3_stream_type_t h3_stream_type = h3_stream->h3_stream_type;
    if(h3_stream_type == XQC_H3_STREAM_CONTROL || h3_stream_type == XQC_H3_STREAM_NUM){
        h3_stream->tnode = NULL;
        return 0;
    }else{
        xqc_stream_t * stream = h3_stream->stream;
        xqc_http3_node_id_t nid;
        nid.id = stream->stream_id;
        if(h3_stream_type == XQC_H3_STREAM_REQUEST){
            nid.type = XQC_HTTP3_PRI_ELEM_TYPE_REQUEST;
        }else if (h3_stream_type == XQC_H3_STREAM_PUSH){
            nid.type = XQC_HTTP3_PRI_ELEM_TYPE_PUSH;
        }else{
            return -1;
        }

        h3_stream->tnode = xqc_tnode_hash_find_by_id(&h3_conn->tnode_hash, &nid);
        if(h3_stream->tnode == NULL){
            h3_stream->tnode = xqc_http3_create_tnode(&h3_conn->tnode_hash, &nid, XQC_HTTP3_DEFAULT_WEIGHT, h3_conn->tnode_root);
        }
        if (h3_stream->tnode == NULL){
            return -1;
        }else{
            //h3_stream->tnode->h3_stream = h3_stream;
        }

    }
#endif
    return 0;
}

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

    xqc_h3_stream_read_state_init(&h3_stream->read_state);

    h3_stream->flags = XQC_HTTP3_STREAM_FLAG_NONE;
    h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_NONE;
    h3_stream->tx_http_state = XQC_HTTP3_HTTP_STATE_NONE;

    xqc_init_list_head(&h3_stream->send_frame_data_buf);

    xqc_init_list_head(&h3_stream->recv_header_data_buf);
    xqc_init_list_head(&h3_stream->recv_body_data_buf);


    stream->user_data = h3_stream;

    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;

#ifdef XQC_HTTP3_PRIORITY_ENABLE
    //get tnode
    if(h3_conn->conn->conn_type == XQC_CONN_TYPE_SERVER){
        if(xqc_http3_stream_link_tnode(h3_stream) < 0){
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|stream link tnode error|");
            return NULL;
        }
    }
#endif


    return h3_stream;
}

int xqc_h3_stream_read_state_init(xqc_http3_stream_read_state * read_state){
    memset(read_state, 0, sizeof(xqc_http3_stream_read_state));
    return 0;
}


void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream->h3_request) {
        xqc_h3_request_destroy(h3_stream->h3_request);
    }
#ifdef XQC_HTTP3_PRIORITY_ENABLE
    if(h3_stream->tnode){
        xqc_http3_tnode_free(h3_stream->tnode);
    }
#endif
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|",
            h3_stream->stream->stream_id, h3_stream->h3_stream_type);
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

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|", stream->stream_id);
    return XQC_OK;
}

ssize_t
xqc_h3_stream_send(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;
    if (h3_stream->h3_stream_type == XQC_H3_STREAM_REQUEST &&
        (h3_conn->flags & XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD) &&
        h3_stream->stream->stream_id >= h3_conn->goaway_stream_id) {

        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|goaway recvd, stop send|");
        return -XQC_H3_EGOAWAY;
    }
    ssize_t n_write = 0;
    n_write = xqc_stream_send(h3_stream->stream, data, data_size, fin);
    if (n_write < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_send error|%z|", n_write);
        return n_write;
    }
    return n_write;
}

ssize_t
xqc_h3_stream_send_headers(xqc_h3_stream_t *h3_stream, xqc_http_headers_t *headers)
{
    ssize_t n_write = 0;
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;
    //QPACK
    //gen HEADERS frame
    unsigned char buf[200]; ssize_t len=200;
    uint8_t fin = 0;
    n_write = xqc_http3_write_frame_header(h3_stream, buf, len, fin);
    if (n_write < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_write_frame_header error|%z|", n_write);
        return n_write;
    }
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|n_write:%i|", n_write);
    xqc_engine_main_logic(h3_stream->h3_conn->conn->engine);
    return n_write;
}

ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    ssize_t n_write = 0;

    n_write = xqc_http3_write_frame_data(h3_stream, data, data_size, fin); //TODO:fin
    if (n_write < 0) {
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_write_frame_data error|%z|", n_write);
        return n_write;
    }
    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|n_write:%i|", n_write);
    xqc_engine_main_logic(h3_stream->h3_conn->conn->engine);
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
    /*return xqc_stream_recv(h3_stream->stream, recv_buf, recv_buf_size, fin);*/

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
            return n_recved;
        } else {
            memcpy(recv_buf + n_recved, h3_data_buf->data + h3_data_buf->already_consume, h3_data_buf_left);
            n_recved += h3_data_buf_left;
            h3_data_buf->already_consume += h3_data_buf_left;
            recv_buf_left -= h3_data_buf_left;
            if (h3_data_buf->fin) {
                *fin = 1;
            }
            xqc_list_del_init(pos);
            xqc_free(pos);
            if (0 == recv_buf_left) {
                return n_recved;
            }
        }
    }
    return n_recved;
}

int
xqc_h3_stream_process_in(xqc_h3_stream_t *h3_stream, unsigned char *data, size_t data_size, uint8_t fin)
{
    ssize_t processed = 0;
    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|data_size:%z|",
            h3_stream->stream->stream_id, h3_stream->h3_stream_type, data_size);
    if (XQC_H3_STREAM_NUM == h3_stream->h3_stream_type) {
        if (h3_stream->stream->stream_type == XQC_SVR_BID || h3_stream->stream->stream_type == XQC_CLI_BID) {
            h3_stream->h3_stream_type = XQC_H3_STREAM_REQUEST;
        } else {
            h3_stream->h3_stream_type = XQC_H3_STREAM_CONTROL;
            h3_conn->control_stream_in = h3_stream;
        }
        if(h3_conn->conn->conn_type == XQC_CONN_TYPE_SERVER){
            if(xqc_http3_stream_link_tnode(h3_stream) < 0){
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|stream link tnode error|");
                return -1;
            }
        }
    }

    if (XQC_H3_STREAM_CONTROL == h3_stream->h3_stream_type) {
        processed = xqc_http3_conn_read_control(h3_conn, h3_stream, data, data_size);
        if (processed < 0 || processed != data_size) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_control error|%z|", processed);
            return -1;
        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_http3_conn_read_control|%z|", processed);
    } else if (XQC_H3_STREAM_REQUEST == h3_stream->h3_stream_type) {
        size_t nproc;
        processed = xqc_http3_conn_read_bidi(h3_conn, &nproc, h3_stream, data, data_size, fin);
        if (processed < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error|%z|", processed);
            return -1;
        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_http3_conn_read_bidi|%z|", processed);
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

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|stream_type:%d|stream_id:%ui|",
            h3_stream->h3_stream_type, h3_stream->stream->stream_id);

    if (h3_stream->h3_stream_type == XQC_H3_STREAM_REQUEST) {
        xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf);

        ret = h3_stream->h3_request->request_if->h3_request_write_notify(h3_stream->h3_request,
                                                                         h3_stream->h3_request->user_data);
        if (ret) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|h3_request_write_notify error|%d|", ret);
            return ret;
        }
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|success|");
    }

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
        h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_NUM, NULL);
    } else {
        h3_stream = (xqc_h3_stream_t *) user_data;
    }

    if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD && stream->stream_id >= h3_conn->goaway_stream_id) {
        //send stop_sending
        return xqc_write_stop_sending_to_packet(h3_conn->conn, stream, HTTP_REQUEST_CANCELLED);
    }

    unsigned char buff[4096] = {0};
    size_t buff_size = 4096;

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
            return read;
        }
        xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", read, fin);

        ret = xqc_h3_stream_process_in(h3_stream, buff, read, fin);
        if (ret < 0) {
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_in error|%d|", ret);
            return ret;
        }

    } while (read == buff_size && !fin);

    if (h3_stream->h3_stream_type == XQC_H3_STREAM_REQUEST) {
        xqc_h3_request_t *h3_request;
        h3_request = h3_stream->h3_request;
        if (!h3_stream->h3_request) {
            h3_request = xqc_h3_request_create_inner(h3_conn, h3_stream, NULL);
            if (!h3_request) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
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

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_DEBUG, "|destroy h3 stream success|h3_stream_type:%d|",
            h3_stream->h3_stream_type);

    xqc_h3_stream_destroy(h3_stream);
    return XQC_OK;
}

const xqc_stream_callbacks_t stream_callbacks = {
        .stream_write_notify = xqc_h3_stream_write_notify,
        .stream_read_notify = xqc_h3_stream_read_notify,
        .stream_close = xqc_h3_stream_close_notify,
};
