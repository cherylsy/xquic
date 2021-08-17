#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"


xqc_h3_blocked_stream_t *
xqc_h3_blocked_stream_create(xqc_h3_stream_t *h3s, uint64_t ricnt)
{
    xqc_h3_blocked_stream_t *blocked_stream = xqc_malloc(sizeof(xqc_h3_blocked_stream_t));
    xqc_init_list_head(&blocked_stream->head);
    blocked_stream->h3s = h3s;
    blocked_stream->ricnt = ricnt;
    return blocked_stream;
}


void
xqc_h3_blocked_stream_free(xqc_h3_blocked_stream_t *blocked_stream)
{
    xqc_list_del(&blocked_stream->head);
    xqc_free(blocked_stream);
}


xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3c, xqc_stream_t *stream, xqc_h3_stream_type_t type,
    void *user_data)
{
    xqc_h3_stream_t *h3s = xqc_calloc(1, sizeof(xqc_h3_stream_t));
    if (!h3s) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3s->stream = stream;
    h3s->h3c = h3c;
    h3s->user_data = user_data;
    h3s->h3r = NULL;
    h3s->type = type;
    h3s->qpack = xqc_h3_conn_get_qpack(h3c);
    h3s->flags = XQC_HTTP3_STREAM_FLAG_NONE;
    xqc_h3_vint_pctx_clear(&h3s->pctx.type);
    memset(&h3s->pctx.frame_pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    h3s->blocked = XQC_FALSE;
    xqc_init_list_head(&h3s->send_buf);
    xqc_init_list_head(&h3s->blocked_buf);
    h3s->ctx = xqc_qpack_create_req_ctx(stream->stream_id);
    h3s->log = h3c->log;

    stream->user_data = h3s;
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;

    return h3s;
}


void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3s)
{
    if (h3s->h3r) {
        xqc_h3_request_destroy(h3s->h3r);
    }
    xqc_h3_frm_reset_pctx(&h3s->pctx.frame_pctx);
    xqc_qpack_destroy_req_ctx(h3s->ctx);
    xqc_list_buf_list_free(&h3s->send_buf);
    xqc_list_buf_list_free(&h3s->blocked_buf);

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|",
            h3s->stream->stream_id, h3s->type);

    xqc_free(h3s);
}


xqc_int_t
xqc_h3_stream_send_buffer(xqc_h3_stream_t *h3s)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &h3s->send_buf) {
        xqc_list_buf_t *list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = list_buf->buf;

        if (buf->data != NULL) {
            if (buf->consumed_len < buf->data_len) {
                /* send buffer with transport stream */
                ssize_t sent = xqc_stream_send(h3s->stream, buf->data + buf->consumed_len,
                                               buf->data_len - buf->consumed_len, buf->fin_flag);
                if (sent == -XQC_EAGAIN) {
                    return -XQC_EAGAIN;

                } else if (sent < 0) {
                    xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_send error|ret:%z|", sent);
                    return sent;
                }

                buf->consumed_len += sent;
                if (buf->consumed_len != buf->data_len) {
                    return -XQC_EAGAIN;
                }
            } else if (buf->data_len > 0) {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is empty|buf->consumed_len:%d|buf->data_len:%d",
                        buf->consumed_len, buf->data_len);
            }
        } else {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is NULL|");
        }

        xqc_list_buf_free(list_buf);
    }

    return XQC_OK;
}


static inline uint64_t
xqc_h3_uncompressed_fields_size(xqc_http_headers_t *headers)
{
    /* The size of a field list is calculated based on the uncompressed size of fields, including
       the length of the name and value in bytes plus an overhead of 32 bytes for each field */
    return headers->total_len + headers->count * 32;
}


ssize_t
xqc_h3_stream_write_headers(xqc_h3_stream_t *h3s,
                            xqc_http_headers_t *headers, uint8_t fin)
{
    ssize_t processed = 0;

    /* prepare buf for encoded field section size */
    size_t buf_size = xqc_max(XQC_VAR_BUF_INIT_SIZE, headers->total_len);   /* larger is better */
    xqc_var_buf_t *data = xqc_var_buf_create(buf_size);
    if (data == NULL) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|malloc error|stream_id:%ui|fin:%d|",
                h3s->stream->stream_id, fin);
        return -XQC_EMALLOC;
    }

    /* encode headers with qpack */
    xqc_int_t ret = xqc_qpack_enc_headers(h3s->qpack, h3s->stream->stream_id, headers, data);
    if (ret != XQC_OK) {
        xqc_var_buf_free(data);
        return ret;
    }
    processed += data->data_len;

    /* write HEADERS frame */
    ret = xqc_h3_frm_write_headers(&h3s->send_buf, data, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write HEADERS frame error|stream_id:%ui|fin:%d|",
                h3s->stream->stream_id, fin);
        xqc_var_buf_free(data);
        return ret;
    }

    /* send HEADERS frame */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret == -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|send HEADERS frame eagain|stream_id:%ui|fin:%d|",
                h3s->stream->stream_id, fin);
        return processed;

    } else if(ret < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send HEADERS frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream->stream_id, fin);
        processed = ret;
    }

    return processed;
}


ssize_t
xqc_h3_stream_write_data_to_buffer(xqc_h3_stream_t *h3s, unsigned char* data, uint64_t data_size,
    uint8_t fin)
{
    uint64_t write = 0;
    uint64_t size;
    uint8_t flag;
    xqc_int_t ret;

    do {
        /* truncate data if it is too large */
        if (data_size > write + XQC_H3_STREAM_MAX_FRM_PAYLOAD) {
            size = XQC_H3_STREAM_MAX_FRM_PAYLOAD;
            flag = 0;

        } else {
            size = data_size - write;
            flag = fin;
        }

        /* write DATA frame */
        ret = xqc_h3_frm_write_data(&h3s->send_buf, data + write, size, flag);
        if (ret != XQC_OK) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|write DATA frame error|%d|stream_id:%ui|fin:%d|",
                    ret, h3s->stream->stream_id, fin);
            return ret;
        }
        write += size;

        /* send DATA frame */
        ret = xqc_h3_stream_send_buffer(h3s);
        if (ret == -XQC_EAGAIN) {
            return write;

        } else if (ret < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|send DATA frame error|%d|stream_id:%ui|fin:%d|",
                    ret, h3s->stream->stream_id, fin);
            return ret;
        }

    } while (data_size > write);

    return write;
}


xqc_int_t
xqc_h3_stream_write_setting_to_buffer(xqc_h3_stream_t *h3s, xqc_h3_conn_settings_t *settings, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_frm_write_settings(&h3s->send_buf, settings, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write SETTINGS frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream->stream_id, fin);
        return ret;
    }

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send SETTINGS frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream->stream_id, fin);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_write_goaway_to_buffer(xqc_h3_stream_t *h3s, uint64_t push_id, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_frm_write_goaway(&h3s->send_buf,push_id, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write GOAWAY frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream->stream_id, fin);
        return ret;
    }

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send GOAWAY frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream->stream_id, fin);
        return ret;
    }

    return XQC_OK;
}


ssize_t
xqc_h3_stream_send_headers(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, uint8_t fin)
{
    /* nothing to send */
    if (headers->count == 0) {
        return 0;
    }

    xqc_h3_conn_t *h3c = h3s->h3c;

    /* header size constrains */
    uint64_t fields_size = xqc_h3_uncompressed_fields_size(headers);
    uint64_t max_field_section_size = h3c->peer_h3_conn_settings.max_field_section_size;
    if (fields_size > max_field_section_size) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|large nv|conn:%p|fields_size:%ui|exceed|"
                "SETTINGS_MAX_FIELD_SECTION_SIZE:%ui|", h3c->conn, fields_size, 
                max_field_section_size);
        return -XQC_H3_INVALID_HEADER;
    }

    h3s->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    /* QPACK & gen HEADERS frame */
    ssize_t write = xqc_h3_stream_write_headers(h3s, headers, fin);
    if (write < 0) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_write_headers error|ret:%z||stream_id:%ui",
                write, h3s->stream->stream_id);
        XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR, write);
    }

    /* header_sent is the sum of plaintext header name value length */
    h3s->h3r->header_sent += headers->total_len;

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|write:%z|stream_id:%ui|fin:%d|conn:%p|flag:%s|", write,
            h3s->stream->stream_id, fin, h3c->conn, xqc_conn_flag_2_str(h3c->conn->conn_flag));

    h3s->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    xqc_engine_main_logic_internal(h3c->conn->engine, h3c->conn);

    return write;
}


ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_size, uint8_t fin)
{
    h3s->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    /* write data to DATA frame and add to buffere */
    ssize_t write = xqc_h3_stream_write_data_to_buffer(h3s, data, data_size, fin);
    if (write < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write data to buffer error|");
        return write;
    }

    if (write == data_size) {
        h3s->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    }

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%uz|write:%z|fin:%d|conn:%p|",
            h3s->stream->stream_id, data_size, write, fin, h3s->h3c->conn);

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine, h3s->h3c->conn);

    return write;
}


xqc_int_t
xqc_h3_stream_send_uni_stream_hdr(xqc_h3_stream_t *h3s)
{
    size_t len = xqc_vint_len_by_val(h3s->type);
    xqc_var_buf_t *buf = xqc_var_buf_create(len);
    if (buf == NULL) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|create buf for uni-stream type error|stream_id:%ui",
                h3s->stream->stream_id);
        return -XQC_EMALLOC;
    }

    /* write uni stream type */
    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, h3s->type);
    buf->data_len = pos - buf->data;

    xqc_int_t ret = xqc_list_buf_to_tail(&h3s->send_buf, buf);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|add uni-stream hdr to send buf error|%d|stream_id:%ui",
                ret, h3s->stream->stream_id);
        xqc_var_buf_free(buf);
        return ret;
    }

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send uni-stream hdr error|%d|stream_id:%ui",
                ret, h3s->stream->stream_id);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_send_setting(xqc_h3_stream_t *h3s, xqc_h3_conn_settings_t *settings, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_stream_write_setting_to_buffer(h3s, settings, fin);
    if (ret < 0) {
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_send_goaway(xqc_h3_stream_t *h3s, uint64_t push_id, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_stream_write_goaway_to_buffer(h3s, push_id, fin);
    if (ret < 0) {
        return ret;
    }

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine, h3s->h3c->conn);

    return XQC_OK;
}


int
xqc_h3_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    int ret;
    /* server h3_stream might not be created yet */
    if (!user_data) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|user_data empty|");
        return XQC_OK;
    }

    xqc_h3_stream_t *h3s = (xqc_h3_stream_t*) user_data;
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_type:%d|stream_id:%ui|conn:%p|",
            h3s->type, h3s->stream->stream_id, stream->stream_conn);

    /* send frame buffer */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret == -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_DEBUG,
                "|send buf eagain|stream_id:%ui|",
                h3s->stream->stream_id);
        return XQC_OK;
    } else if (ret < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR,
                "|send buf error|%z|stream_id:%ui|",
                h3s->stream->stream_id, ret);
        XQC_H3_CONN_ERR(h3s->h3c, H3_INTERNAL_ERROR, ret);
        return ret;
    }

    /* request write  */
    if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST
        && (h3s->flags & XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY))
    {
        ret = h3s->h3r->request_if->h3_request_write_notify(h3s->h3r, h3s->h3r->user_data);
        if (ret < 0) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|h3_request_write_notify error|%d|", ret);
            return ret;
        }
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|h3_request_write_notify|success|");
    }

    return XQC_OK;
}


ssize_t
xqc_h3_stream_process_control(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    xqc_h3_conn_t *h3c = h3s->h3c;
    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;

    ssize_t processed = 0;
    while (processed < data_len) {
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        processed += read;

        if (pctx->state != XQC_H3_FRM_STATE_END && data_len != processed) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|parse frame state error|state:%d||data_len:%zu|"
                    "processed:%zu|", pctx->state, data_len, processed);
            xqc_h3_frm_reset_pctx(pctx);
            return -XQC_H3_DECODE_ERROR;
        }

        if (pctx->frame.type != XQC_H3_FRM_SETTINGS
            && !(h3s->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED))
        {
            xqc_h3_frm_reset_pctx(pctx);
            return -H3_FRAME_UNEXPECTED;
        }

        if (pctx->state == XQC_H3_FRM_STATE_END) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_CANCEL_PUSH:
                /* TODO: not implemented */
                break;

            case XQC_H3_FRM_SETTINGS:
                if (h3s->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return -H3_FRAME_UNEXPECTED;
                }

                h3s->h3c->flags |= XQC_H3_CONN_FLAG_SETTINGS_RECVED;

                if (xqc_h3_frm_parse_setting(pctx->frame.frame_payload.settings.setting,
                                             (void *)h3c) < 0)
                {
                    xqc_h3_frm_reset_pctx(pctx);
                    return -H3_SETTINGS_ERROR;
                }
                break;

            case XQC_H3_FRM_GOAWAY:
                if (h3c->goaway_stream_id > pctx->frame.frame_payload.goaway.push_id.vi) {
                    h3c->goaway_stream_id = pctx->frame.frame_payload.goaway.push_id.vi;

                } else {
                    xqc_log(h3c->log, XQC_LOG_WARN, "|xqc_h3_stream_process_control goaway_frame"
                            " receive bigger push id|push_id:%ui|",
                            pctx->frame.frame_payload.goaway.push_id.vi);
                }
                h3s->h3c->flags |= XQC_H3_CONN_FLAG_GOAWAY_RECVD;
                break;

            case XQC_H3_FRM_MAX_PUSH_ID:
                // push相关暂不实现
                h3c->max_stream_id_recvd = pctx->frame.frame_payload.max_push_id.push_id.vi;
                break;

            default:
                xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_control error|error frame type:%z|", pctx->frame.type);
                xqc_h3_frm_reset_pctx(pctx);
                return -H3_FRAME_UNEXPECTED;
            }

            xqc_h3_frm_reset_pctx(pctx);
        }
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_push(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    size_t processed = 0;

    while (processed < data_len) {
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        processed += read;

        if (pctx->state != XQC_H3_FRM_STATE_END && data_len != processed) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame state error|state:%d||data_len:%zu|"
                    "processed:%zu|", pctx->state, data_len, processed);
            xqc_h3_frm_reset_pctx(pctx);
            return -XQC_H3_DECODE_ERROR;
        }

        if (pctx->state == XQC_H3_FRM_STATE_END) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_HEADERS:
                // push相关暂不实现
                break;
            case XQC_H3_FRM_DATA:
                // push相关暂不实现
                break;
            default:
                xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_push error|error"
                        " frame type:%z|", pctx->frame.type);
                xqc_h3_frm_reset_pctx(pctx);
                return -H3_FRAME_UNEXPECTED;
            }
            xqc_h3_frm_reset_pctx(pctx);
        }
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_request(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len, xqc_bool_t fin_flag)
{
    if (h3s->h3r == NULL) {
        h3s->h3r = xqc_h3_request_create_inner(h3s->h3c, h3s, h3s->user_data);
    }

    if (data_len == 0) {
        return 0;
    }

    if (data == NULL) {
        return -XQC_H3_EPARAM;
    }

    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    ssize_t processed = 0;
    ssize_t len = 0;
    xqc_int_t ret;

    while (processed < data_len) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame|state:%d|data_len:%d|process:%d|",
                pctx->state, data_len, processed);

        /* parse frame, mainly the type, length field */
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame error|ret:%d|state:%d|frame_type:%d|",
                    read, pctx->state, pctx->frame.type);
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame success|frame_type:%d|read:%d|",
                pctx->frame.type, read);
        processed += read;

        xqc_bool_t fin = pctx->state == XQC_H3_FRM_STATE_END ? XQC_TRUE : XQC_FALSE;

        /* begin to parse the payload of a frame */
        if (pctx->state >= XQC_H3_FRM_STATE_PAYLOAD) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_HEADERS:
                /* the previous headers shall be read, or it might cause errors */
                if (h3s->h3r->h3_header.read_flag == XQC_H3_REQUEST_HEADER_DATA) {
                    xqc_log(h3s->log, XQC_LOG_WARN, "|prev header still not read|");
                }

                len = xqc_min(pctx->frame.len, data_len - processed);
                read = xqc_qpack_dec_headers(h3s->qpack, h3s->ctx,
                                             data + processed, len,
                                             &h3s->h3r->h3_header.headers, fin, &h3s->blocked);
                if (read < 0) {
                    xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_request error"
                            "|error frame type:%z|", pctx->frame.type);
                    xqc_h3_frm_reset_pctx(pctx);
                    return -XQC_QPACK_SAVE_HEADERS_ERROR;
                }
                processed += read;
                pctx->frame.len -= read;

                /* stream blocked, wait for dynamic table entries */
                if (h3s->blocked) {
                    xqc_log(h3s->log, XQC_LOG_DEBUG, "|request stream blocked|stream_id:%ui|",
                            h3s->stream->stream_id);
                    return processed;
                }

                if (pctx->frame.len == 0) {
                    fin = 1;
                    h3s->h3r->header_frame_count++;
                    if (h3s->h3r->header_frame_count > 1) {
                        xqc_log(h3s->log, XQC_LOG_DEBUG, "|headers_frame_count exceed 1|"
                                "stream_id:%ui|cnt:%uz|", h3s->stream->stream_id,
                                h3s->h3r->header_frame_count);
                    }

                    xqc_h3_frm_reset_pctx(pctx);
                    xqc_qpack_clear_req_ctx(h3s->ctx);
                    if (fin_flag && processed == data_len) {
                        h3s->h3r->fin_flag = fin_flag;
                    }

                    ret = xqc_h3_request_on_recv_header(h3s->h3r);
                    if (ret != XQC_OK) {
                        xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_request_on_recv error|%d|", ret);
                        return ret;
                    }
                }
                break;

            case XQC_H3_FRM_DATA:
                len = xqc_min(pctx->frame.len, data_len - processed);
                xqc_var_buf_t *buf = xqc_var_buf_create(len);
                if (buf == NULL) {
                    return -XQC_EMALLOC;
                }
                ret = xqc_var_buf_save_data(buf, data + processed, len);
                if (ret != XQC_OK) {
                    xqc_var_buf_free(buf);
                    xqc_h3_frm_reset_pctx(pctx);
                    return ret;
                }
                ret = xqc_list_buf_to_tail(&h3s->h3r->body_buf, buf);
                if (ret < 0) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return ret;
                }
                h3s->h3r->body_buf_count++;

                processed += len;
                pctx->frame.len -= len;

                if (pctx->frame.len == 0) {
                    fin = 1;
                    if (fin_flag && processed == data_len) {
                        h3s->h3r->fin_flag = fin_flag;
                    }
                }
                break;

            case XQC_H3_FRM_PUSH_PROMISE:
                // push相关暂不实现
                break;

            default:
                xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_request error|error "
                        "frame type:%z|", pctx->frame.type);
                xqc_h3_frm_reset_pctx(pctx);
                return -H3_FRAME_UNEXPECTED;
            }

            if (fin) {
                xqc_h3_frm_reset_pctx(pctx);
            }
        }
    }

    return processed;
}


ssize_t
xqc_h3_stream_process_uni_stream_type(const uint8_t *data, size_t data_len, 
    xqc_discrete_vint_pctx_t *vctx, xqc_bool_t *fin)
{
    /* parse stream type */
    ssize_t nread = xqc_discrete_vint_parse(data, data_len, vctx, fin);
    if (nread < 0) {
        return -XQC_H3_DECODE_ERROR;
    }

    return nread;
}


/* process uni stream payload */
ssize_t
xqc_h3_stream_process_uni_payload(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    ssize_t processed;
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_h3_stream_process_uni_payload|type:%d|sz:%ud|",
            h3s->type, data_len);

    switch (h3s->type) {
    case XQC_H3_STREAM_TYPE_CONTROL:
        processed = xqc_h3_stream_process_control(h3s, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_PUSH:
        processed = xqc_h3_stream_process_push(h3s, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_QPACK_ENCODER:
        processed = xqc_qpack_process_encoder(h3s->qpack, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_QPACK_DECODER:
        processed = xqc_qpack_process_decoder(h3s->qpack, data, data_len);
        break;

    /* bytes from reserved stream type will be ignored */
    default:
        processed = data_len;
        break;
    }

    return processed;
}


ssize_t
xqc_h3_stream_process_uni(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    ssize_t processed = 0;

    /* uni-stream header indicates stream type, parse stream type */
    if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)) {
        xqc_bool_t fin = XQC_FALSE;  /* finish flag of parse stream type */
        ssize_t read = xqc_h3_stream_process_uni_stream_type(data + processed, data_len - processed,
                                                             &h3s->pctx.type, &fin);
        if (read < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse uni-stream type error|ret:%ui|", read);
            return read;
        }
        processed += read;

        /* exception, parsing not finished while bytes remaining */
        if (!fin && processed != data_len) {
            xqc_log(h3s->log, XQC_LOG_ERROR,
                    "|parse uni-stream type state error|ret:%ui", processed);
            XQC_H3_CONN_ERR(h3s->h3c, H3_FRAME_ERROR, -XQC_H3_DECODE_ERROR);
            return -XQC_H3_DECODE_ERROR;
        }

        if (fin) {
            /* check legistimation of uni-stream */
            h3s->type = h3s->pctx.type.vi;
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED;
            xqc_h3_vint_pctx_clear(&h3s->pctx.type);

            if (xqc_h3_conn_on_uni_stream_created(h3s->h3c, h3s->type) != XQC_OK) {
                return -XQC_H3_INVALID_STREAM;
            }

            if (fin) {
                xqc_h3_vint_pctx_clear(&h3s->pctx.type);
            }
        }
    }

    if (data_len != processed) {
        /* deliver data to modules which is concerned */
        ssize_t read = xqc_h3_stream_process_uni_payload(h3s, data + processed,
                                                         data_len - processed);
        if (read < 0 || read + processed != data_len) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|error processing uni-stream payload|type:%d|"
                    "sz:%uz|processed:%z|", h3s->type, data_len, read);
            return -XQC_H3_DECODE_ERROR;
        }
        processed += read;
    }

    return processed;
}


/* process bidi stream payload */
ssize_t
xqc_h3_stream_process_bidi_payload(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len, xqc_bool_t fin_flag)
{
    ssize_t processed;
    switch (h3s->type) {
    case XQC_H3_STREAM_TYPE_REQUEST:
        processed = xqc_h3_stream_process_request(h3s, data, data_len, fin_flag);
        break;

    /* bytes from reserved stream type will be ignored */
    default:
        processed = data_len;
        break;
    }

    return processed;
}


ssize_t
xqc_h3_stream_process_bidi(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len, xqc_bool_t fin_flag)
{
    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
        return 0;
    }

    if (XQC_H3_STREAM_TYPE_UNKNOWN == h3s->type) {
        h3s->type = XQC_H3_STREAM_TYPE_REQUEST;
        if (!h3s->h3r) {
            h3s->h3r = xqc_h3_request_create_inner(h3s->h3c, h3s, NULL);
            if (!h3s->h3r) {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
                return -XQC_H3_ECREATE_REQUEST;
            }
        }
    }

    return xqc_h3_stream_process_bidi_payload(h3s, data, data_len, fin_flag);
}


xqc_int_t
xqc_h3_stream_process_in(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len, xqc_bool_t fin_flag)
{
    ssize_t processed;
    xqc_h3_conn_t *h3c = h3s->h3c;
    if (data_len == 0) {
        return XQC_OK;
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|data_size:%z|",
            h3s->stream->stream_id, h3s->type, data_len);

    if (xqc_stream_is_uni(h3s->stream->stream_id)) {
        /* process uni stream bytes */
        processed = xqc_h3_stream_process_uni(h3s, data, data_len);
        if (processed < 0 || processed != data_len) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_uni error|processed:%z"
                    "|size:%uz|stream_id:%ui|", processed, data_len, h3s->stream->stream_id);

            XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, -XQC_H3_EPROC_CONTROL);
            return -XQC_H3_EPROC_CONTROL;
        }

        xqc_log(h3c->log, XQC_LOG_DEBUG, "|xqc_h3_stream_process_uni|%z|", processed);

    } else {
        /* process bidi stream bytes */
        processed = xqc_h3_stream_process_bidi(h3s, data, data_len, fin_flag);
        if (processed < 0) {
            /* error occured */
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_bidi|%z|", processed);
            if (processed == -XQC_H3_INVALID_HEADER) {
                XQC_H3_CONN_ERR(h3c, H3_GENERAL_PROTOCOL_ERROR, -XQC_H3_EPROC_REQUEST);

            } else {
                XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
            }

            return -XQC_H3_EPROC_REQUEST;

        } else if (processed != data_len || h3s->blocked == XQC_TRUE) {
            if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
                xqc_log(h3c->log, XQC_LOG_ERROR, "|h3_stream has been blocked|");
                return XQC_ERROR;

            } else {
                h3s->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;

                /* if blocked, store data in blocked buffer */
                xqc_var_buf_t *buf = xqc_var_buf_create(XQC_DATA_BUF_SIZE_4K);
                if (buf == NULL) {
                    return -XQC_H3_EMALLOC;
                }
                xqc_int_t ret = xqc_var_buf_save_data(buf, data + processed, data_len - processed);
                if (ret != XQC_OK) {
                    xqc_var_buf_free(buf);
                    return ret;
                }

                /* add remained data to blocked buf list */
                ret = xqc_list_buf_to_tail(&h3s->blocked_buf, buf);
                if (ret < 0) {
                    xqc_var_buf_free(buf);
                    return ret;
                }

                ret = xqc_h3_conn_add_blocked_stream(h3c, h3s, xqc_qpack_get_req_rqrd_insert_cnt(h3s->ctx));
                if (ret < 0) {
                    return -XQC_H3_BLOCKED_STREAM_EXCEED;
                }
            }
        }
    }

    return XQC_OK;
}


xqc_var_buf_t *
xqc_h3_stream_get_buf(xqc_h3_stream_t *h3s, xqc_list_head_t *head, size_t expected_size)
{
    xqc_var_buf_t *buf = NULL;

    if (!xqc_list_empty(head)) {
        /* the last in list */
        xqc_list_buf_t *list_buf = xqc_list_entry(head->prev, xqc_list_buf_t, list_head);
        buf = list_buf->buf;

        /* reuse the last buf until it is fully used */
        if (buf->data_len == buf->buf_len) {
            buf = NULL;
        }
    }

    /* can't find a buf, or can't reuse a buf, create a new one  */
    if (buf == NULL) {
        /* no memory buffer or the last is full, create a new one */
        buf = xqc_var_buf_create(expected_size);
        if (buf == NULL) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|create buf error|");
            return NULL;
        }

        xqc_int_t ret = xqc_list_buf_to_tail(head, buf);
        if (ret < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|add new buf to blocked buf error|ret:%d", ret);
            xqc_var_buf_free(buf);
            return NULL;
        }
    }

    return buf;
}


xqc_int_t
xqc_h3_stream_process_blocked_data(xqc_stream_t *stream, xqc_h3_stream_t *h3s, xqc_bool_t *fin)
{
    ssize_t rcvd = 0;
    xqc_var_buf_t *buf = NULL;

    do
    {
        buf = xqc_h3_stream_get_buf(h3s, &h3s->blocked_buf, XQC_DATA_BUF_SIZE_4K);
        if (buf == NULL) {
            return -XQC_EMALLOC;
        }

        /* recv from transport stream, and buffer data to blocked buf list */
        rcvd = xqc_stream_recv(stream, buf->data + buf->data_len, 
                               buf->buf_len - buf->data_len, fin);
        if (rcvd == -XQC_EAGAIN) {
            break;

        } else if (rcvd < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", rcvd);
            return -XQC_H3_STREAM_RECV_ERROR;
        }

        xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", rcvd, *fin);

        buf->data_len += rcvd;
        buf->fin_flag = *fin;

    } while (buf->buf_len == buf->data_len && !*fin);

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_process_data(xqc_stream_t *stream, xqc_h3_stream_t *h3s, xqc_bool_t *fin)
{
    ssize_t read;
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)stream->stream_conn->user_data;
    unsigned char buff[XQC_DATA_BUF_SIZE_4K];
    size_t buff_size = XQC_DATA_BUF_SIZE_4K;
    xqc_int_t ret;
    uint64_t insert_cnt = xqc_qpack_get_dec_insert_count(h3s->qpack);

    do
    {
        /* recv data from transport stream */
        read = xqc_stream_recv(h3s->stream, buff, buff_size, fin);
        if (read == -XQC_EAGAIN) {
            return XQC_OK;

        } else if (read < 0) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
            return -XQC_H3_STREAM_RECV_ERROR;
        }
        xqc_log(h3c->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%d|", read, *fin);

        /* process h3 stream data */
        ret = xqc_h3_stream_process_in(h3s, buff, read, *fin);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_in error|%d|", ret);
            XQC_H3_CONN_ERR(h3s->h3c, H3_INTERNAL_ERROR, ret);
            return ret;
        }

        /* after process in, the stream might be blocked, read all data and add to blocked list */
        if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
            return xqc_h3_stream_process_blocked_data(stream, h3s, fin);
        }

    } while (read == buff_size && !*fin);

    if (*fin) {
        h3s->h3r->fin_flag = *fin;
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;
    }

    if (xqc_qpack_get_dec_insert_count(h3s->qpack) > insert_cnt) {
        ret = xqc_h3_conn_process_blocked_stream(h3s->h3c);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_conn_process_blocked_stream error|ret:%d|"
                    "stream_id:%ui", ret, h3s->stream->stream_id);
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_process_blocked_stream(xqc_h3_blocked_stream_t *blocked_stream)
{
    xqc_h3_stream_t *h3s = blocked_stream->h3s;
    xqc_list_head_t *pos, *next;
    xqc_list_buf_t *list_buf = NULL;

    xqc_h3_conn_delete_blocked_stream(h3s->h3c, blocked_stream);
    h3s->blocked = XQC_FALSE;

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|decode blocked header success|stream_id:%d|", h3s->stream->stream_id);

    xqc_list_for_each_safe(pos, next, &h3s->blocked_buf) {
        list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);

        xqc_var_buf_t *buf = list_buf->buf;
        ssize_t processed = xqc_h3_stream_process_request(h3s, buf->data + buf->consumed_len,
                                                          buf->data_len - buf->consumed_len, buf->fin_flag);
        if (processed < 0) {
            return processed;
        }
        buf->consumed_len += processed;

        if (buf->consumed_len == buf->data_len) {
            xqc_list_buf_free(list_buf);

        } else {
            return XQC_OK;
        }

        if (h3s->blocked) {
            xqc_log(h3s->log, XQC_LOG_DEBUG, "|continue blocked|");
            return XQC_OK;
        }
    }

    h3s->flags &= ~ XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;

    return XQC_OK;
}


int
xqc_h3_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3s;
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)stream->stream_conn->user_data;
    xqc_int_t ret;

    /* server h3_stream might not be created yet */
    if (!user_data) {
        h3s = xqc_h3_stream_create(h3c, stream, XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
        if (!h3s) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
            return -XQC_H3_ECREATE_STREAM;
        }

        xqc_log(h3c->log, XQC_LOG_DEBUG, "|create h3stream|stream_id:%ui", stream->stream_id);

    } else {
        h3s = (xqc_h3_stream_t *)user_data;
    }

    /* in case that read notify */
    if (h3s->flags & XQC_HTTP3_STREAM_IN_READING) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|read again|stream_id:%ui|", stream->stream_id);
        return XQC_OK;
    }
    h3s->flags |= XQC_HTTP3_STREAM_IN_READING;

    /* check goaway */
    if (xqc_h3_conn_is_goaway_recved(h3c, stream->stream_id) == XQC_TRUE) {
        /* peer sent goaway and keep on sending data,
           stop it with STOP_SENDING frame */
        ret = xqc_write_stop_sending_to_packet(h3c->conn, stream, H3_REQUEST_CANCELLED);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_write_stop_sending_to_packet error|%d|", ret);
            h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
            return ret;
        }

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        return XQC_OK;
    }

    xqc_bool_t fin = XQC_FALSE;
    /* if stream is blocked, recv and buffer data */
    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
        ret = xqc_h3_stream_process_blocked_data(stream, h3s, &fin);

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        if (ret == -XQC_H3_STREAM_RECV_ERROR) {
            return XQC_OK;
        } else if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_blocked_data error|%d|", ret);
            return ret;
        }

    } else {
        /* if stream is not blocked, recv data and process */
        ret = xqc_h3_stream_process_data(stream, h3s, &fin);

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        if (ret == -XQC_H3_STREAM_RECV_ERROR) {
            return XQC_OK;
        } else if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_data error|%d|", ret);
            return ret;
        }

        /* after recv and process data, h3_stream shall notify h3_request */
        if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
            ret = xqc_h3_request_on_recv_body(h3s->h3r);
            if (ret != XQC_OK) {
                xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_request_on_recv error|%d|", ret);
                return ret;
            }
        }
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|",
            h3s->stream->stream_id, h3c->conn);

    return XQC_OK;
}


int
xqc_h3_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    if (!(stream->stream_flag & XQC_STREAM_FLAG_HAS_H3)) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|has no h3 stream|");
        return XQC_OK;
    }

    xqc_h3_stream_t *h3s = (xqc_h3_stream_t*)user_data;
    h3s->flags |= XQC_HTTP3_STREAM_FLAG_CLOSED;
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|destroy h3 stream success|h3_stream_type:%d|",
            h3s->type);
    xqc_h3_stream_destroy(h3s);

    return XQC_OK;
}


/**
 * transport callback
 */
const xqc_stream_callbacks_t h3_stream_callbacks = {
        .stream_write_notify = xqc_h3_stream_write_notify,
        .stream_read_notify = xqc_h3_stream_read_notify,
        .stream_close_notify = xqc_h3_stream_close_notify,
};


xqc_var_buf_t *
xqc_h3_stream_get_send_buf(xqc_h3_stream_t *h3s)
{
    return xqc_h3_stream_get_buf(h3s, &h3s->send_buf, XQC_VAR_BUF_INIT_SIZE);
}

