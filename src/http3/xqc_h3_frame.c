#include <xquic/xqc_errno.h>
#include "src/http3/xqc_h3_frame.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/http3/xqc_h3_request.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_id_hash.h"


int xqc_http3_conn_on_max_push_id(xqc_h3_conn_t * conn, uint64_t push_id);
int xqc_h3_conn_on_settings_entry_received(xqc_h3_conn_t * conn, xqc_http3_settings_entry * iv);

ssize_t xqc_http3_conn_read_push(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, uint8_t fin);
int xqc_http3_conn_on_cancel_push(xqc_h3_conn_t * conn, xqc_http3_frame_cancel_push * fr);
int xqc_http3_stream_check_rx_http_state(xqc_h3_stream_t * stream, xqc_http3_stream_http_event event);

int xqc_http3_conn_call_begin_headers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream);
int xqc_http3_conn_call_begin_trailers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream);
int xqc_http3_handle_header_data(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream);
int xqc_http3_handle_body_data_completed(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream);



int xqc_http3_stream_empty_headers_allowed(xqc_h3_stream_t *stream) {
    switch (stream->rx_http_state) {
        case XQC_HTTP3_HTTP_STATE_TRAILERS:
            return 0;
        default:
            return -XQC_H3_DECODE_ERROR;
    }
}

xqc_data_buf_t * xqc_create_data_buf(int buf_size, int data_len){

    xqc_data_buf_t * p_buf = xqc_malloc(sizeof(xqc_data_buf_t) + buf_size);
    if (p_buf == NULL) {
        return NULL;
    }
    
    xqc_init_list_head(&p_buf->list_head);
    p_buf->buf_len = buf_size;
    p_buf->data_len = data_len;
    p_buf->already_consume = 0;
    p_buf->fin_flag = 0;
    return p_buf;
}


int xqc_free_data_buf( xqc_list_head_t * head_list){
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head_list){
        xqc_h3_data_buf_t *data_buf = xqc_list_entry(pos, xqc_h3_data_buf_t, list_head);
        xqc_list_del(pos);
        xqc_free(data_buf);
    }
    return 0;
}


int xqc_h3_stream_free_data_buf(xqc_h3_stream_t *h3_stream){

    xqc_free_data_buf(&h3_stream->send_frame_data_buf);
    xqc_free_data_buf(&h3_stream->recv_data_buf);
    xqc_free_data_buf(&h3_stream->recv_body_data_buf);

    return 0;
}

int xqc_buf_to_tail(xqc_list_head_t * phead , char * data, int data_len, uint8_t fin){

    xqc_data_buf_t * p_buf = xqc_create_data_buf(data_len, data_len);
    if(p_buf == NULL){
        return -1;
    }

    if(data_len > 0){
        memcpy(p_buf->data, data, data_len);
    }
    p_buf->fin_flag = fin;
    xqc_list_add_tail(&p_buf->list_head, phead);
    return 0;
}


/* 
 * fill h3 frame header, return bytes that length and type need
 * return -1 if error
 */
int 
xqc_h3_fill_frame_header(char * buf, uint64_t type, uint64_t length)
{
    char * pos = xqc_put_varint(buf, type);
    if(pos == NULL){
        return -1;
    }
    pos = xqc_put_varint(pos, length);

    if(pos == NULL){
        return -1;
    }

    return (pos - buf);
}


ssize_t 
xqc_h3_frame_write_settings_len(int64_t *ppayloadlen, xqc_http3_frame_settings * fr){

    size_t payloadlen = 0;
    size_t i;

    for(i = 0; i < fr->niv; i++){
        payloadlen += xqc_put_varint_len((int64_t)fr->iv[i].id) + xqc_put_varint_len((int64_t)fr->iv[i].value);

    }

    *ppayloadlen = (int64_t)payloadlen;
    return xqc_put_varint_len(XQC_HTTP3_FRAME_SETTINGS) + xqc_put_varint_len((int64_t)payloadlen) + payloadlen;
}

/** setting format:
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identifier (16)       |           Value (i)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *
 */

int 
xqc_h3_frame_write_settings(uint8_t * buf,  xqc_http3_frame_settings * fr)
{
    int nwrite = 0;

    if(fr->niv > MAX_SETTING_ENTRY){
        return -XQC_H3_SETTING_ERROR;
    }

    nwrite = xqc_h3_fill_frame_header(buf, fr->hd.type, fr->hd.length);
    if(nwrite < 0){
        return -XQC_H3_SETTING_ERROR;
    }

    uint8_t * cur_buf = buf + nwrite;
    int i = 0;
    for (i = 0; i < fr->niv; ++i) {
        cur_buf = xqc_put_varint(cur_buf, (int64_t)fr->iv[i].id);
        if(cur_buf == NULL){
            return -XQC_H3_SETTING_ERROR;
        }
        cur_buf = xqc_put_varint(cur_buf, (int64_t)fr->iv[i].value);
        if(cur_buf == NULL){
            return -XQC_H3_SETTING_ERROR;
        }
    }

    return (cur_buf - buf);
}


int xqc_http3_frame_write_hd_len( xqc_http3_frame_hd *hd){

    return xqc_put_varint_len(hd->type) + xqc_put_varint_len(hd->length);
}

int xqc_http3_frame_write_push_promise(){

    //need finish
    return 0;
}

int xqc_http3_frame_write_cancel_push_len(int64_t * ppayloadlen, xqc_http3_frame_cancel_push * fr){

    size_t payloadlen = xqc_put_varint_len(fr->push_id);

    *ppayloadlen = (int64_t) payloadlen;

    return xqc_put_varint_len(XQC_HTTP3_FRAME_CANCEL_PUSH) + xqc_put_varint_len( (uint64_t)payloadlen) + payloadlen;
}

int xqc_http3_frame_write_cancel_push( uint8_t * buf, xqc_http3_frame_cancel_push * fr){

    int nwrite = 0;
    nwrite = xqc_h3_fill_frame_header(buf, fr->hd.type, fr->hd.length);

    if(nwrite < 0){
        return -1;
    }

    uint8_t * cur_buf = buf + nwrite;

    cur_buf = xqc_put_varint(cur_buf, fr->push_id);

    return (cur_buf - buf);

}


int xqc_http3_frame_write_max_push_id_len(int64_t * ppayloadlen, xqc_http3_frame_max_push_id * fr){
    size_t payloadlen = xqc_put_varint_len(fr->push_id);

    *ppayloadlen = (int64_t) payloadlen;

    return xqc_put_varint_len(XQC_HTTP3_FRAME_MAX_PUSH_ID) + xqc_put_varint_len((int64_t)payloadlen) + payloadlen;

}

int xqc_http3_frame_write_max_push_id(uint8_t * buf, xqc_http3_frame_max_push_id *fr){
    int nwrite = 0;
    nwrite = xqc_h3_fill_frame_header(buf, fr->hd.type, fr->hd.length);

    if(nwrite < 0){
        return -1;
    }

    uint8_t * cur_buf = buf + nwrite;

    cur_buf = xqc_put_varint(cur_buf, fr->push_id);

    return (cur_buf - buf);
}


//read variable int util read compeleted, return -1 if error, return read bytes if success
ssize_t xqc_http3_read_varint(xqc_http3_varint_read_state * rvint, uint8_t *src, size_t srclen){
    size_t nread = 0 ;
    size_t n,i;

    if(srclen <= 0){ //means no data need decode
        return -1;
    }

    if(rvint->left == 0){//start decode the varint

        if(rvint->acc != 0){
            return -1; //means rvint state error
        }

        rvint->left = xqc_get_varint_len(src); //decode varint length
        if(rvint->left <= srclen){
            rvint->acc = xqc_get_varint(&nread, src);
            rvint->left = 0;
            return (ssize_t)nread;
        }

        rvint->acc = xqc_get_varint_fb(src); //read first byte
        nread = 1;
        ++src;
        --srclen;
        --rvint->left;
    }

    n = xqc_min(rvint->left, srclen);

    for(i=0; i<n; i++){ //read other bytes
        rvint->acc = (rvint->acc << 8) + src[i];
    }

    rvint->left -= n;
    nread += n;

    return (ssize_t)nread;

}

void xqc_http3_varint_read_state_clear(xqc_http3_varint_read_state *rvint) {
    memset(rvint, 0, sizeof(*rvint));
}

void xqc_http3_stream_read_state_clear(xqc_http3_stream_read_state *rstate) {
    memset(rstate, 0, sizeof(*rstate));
}

ssize_t xqc_http3_read_control_stream_type(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){

    xqc_http3_stream_read_state * read_state = & h3_stream->read_state;
    xqc_http3_varint_read_state * rvint = & read_state->rvint;

    ssize_t nread;
    int64_t stream_type;

    nread = xqc_http3_read_varint(rvint, src, srclen);

    if(nread < 0){
        return -XQC_H3_DECODE_ERROR;
    }

    if(rvint->left){
        return nread; // means variable integer not read competely
    }

    stream_type = rvint->acc;
    xqc_http3_varint_read_state_clear(rvint);

    switch(stream_type){
        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_CONTROL_OPENED) {

                XQC_CONN_ERR(h3_conn->conn, H3_STREAM_CREATION_ERROR);
                return -XQC_H3_INVALID_STREAM;
            }
            h3_conn->flags |= XQC_HTTP3_CONN_FLAG_CONTROL_OPENED;
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_CONTROL;
            read_state->state = XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE;
            break;
        case XQC_HTTP3_STREAM_TYPE_PUSH:
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_PUSH;
            read_state->state = XQC_HTTP3_PUSH_STREAM_STATE_PUSH_ID;
            break;
        case XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER:
            if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_QPACK_ENCODER_OPENED){
                XQC_CONN_ERR(h3_conn->conn, H3_STREAM_CREATION_ERROR);
                return -XQC_H3_INVALID_STREAM;
            }
            h3_conn->flags |= XQC_HTTP3_CONN_FLAG_QPACK_ENCODER_OPENED;
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER;
            break;
        case XQC_HTTP3_STREAM_TYPE_QPACK_DECODER:
            if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_QPACK_DECODER_OPENED) {
                XQC_CONN_ERR(h3_conn->conn, H3_STREAM_CREATION_ERROR);
                return -XQC_H3_INVALID_STREAM;
            }
            h3_conn->flags |= XQC_HTTP3_CONN_FLAG_QPACK_DECODER_OPENED;
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_QPACK_DECODER;
            break;

        default:
            h3_stream->h3_stream_type = XQC_HTTP3_STREAM_TYPE_UNKNOWN;
            break;
    }

    h3_stream->flags |= XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED;

    return nread;
}

ssize_t xqc_http3_conn_read_qpack_encoder(xqc_h3_conn_t * conn,  uint8_t *src, size_t srclen) {

    int insert_count = 0;
    ssize_t nconsumed = xqc_http3_qpack_decoder_read_encoder(conn, src, srclen, &insert_count);

    if(nconsumed < 0){

        return nconsumed;
    }

    if(insert_count > 0){
        xqc_qpack_decoder_block_stream_check_and_process(conn, conn->qdec.ctx.next_absidx);

        if(conn->qdec.written_icnt < conn->qdec.ctx.next_absidx){
            xqc_h3_qpack_decoder_write_insert_count_increment(conn->qdec_stream, conn->qdec.ctx.next_absidx - conn->qdec.written_icnt);
            conn->qdec.written_icnt = conn->qdec.ctx.next_absidx;

        }
    }
    return nconsumed;

}

ssize_t 
xqc_h3_conn_read_qpack_decoder(xqc_h3_conn_t *conn, int8_t *src, size_t srclen)
{
    return xqc_h3_qpack_encoder_read_decoder(conn, src, srclen);
}

ssize_t xqc_http3_conn_read_uni( xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, int fin){

    ssize_t nread = 0;
    ssize_t nconsumed = 0;
    size_t push_nproc;

    int rv;

    if(srclen == 0){
        return 0;
    }

    if(!(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)){
        nread = xqc_http3_read_control_stream_type(h3_conn, h3_stream, src, srclen);
       if(nread < 0){
            return nread;
        }
        if (!(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)){

            if(nread == srclen){
                return nread;
            }else{
                XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                return -XQC_H3_DECODE_ERROR; // means decoder not completely
            }
        }

        src += nread;
        srclen -= (size_t)nread;

        if(srclen == 0){
            return nread;
        }
    }

    switch(h3_stream->h3_stream_type){

        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            if(fin){
                return -XQC_H3_CLOSE_CRITICAL_STREAM;
            }
            nconsumed = xqc_http3_conn_read_control(h3_conn, h3_stream, src, srclen);
            break;
        case XQC_HTTP3_STREAM_TYPE_PUSH:

            if(fin){
                h3_stream->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;
            }
            nconsumed = xqc_http3_conn_read_push(h3_conn, &push_nproc, h3_stream, src, srclen, fin);
            break;
        case XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER:
            if(fin){
                return -XQC_H3_CLOSE_CRITICAL_STREAM;
            }
            nconsumed = xqc_http3_conn_read_qpack_encoder(h3_conn, src, srclen);
            break;

        case XQC_HTTP3_STREAM_TYPE_QPACK_DECODER:
            if(fin){
                return -XQC_H3_CLOSE_CRITICAL_STREAM;
            }
            nconsumed = xqc_h3_conn_read_qpack_decoder(h3_conn, src, srclen);
            break;

        case XQC_HTTP3_STREAM_TYPE_UNKNOWN:
            nconsumed = (ssize_t)srclen;
            //need stop stream
            xqc_log(h3_conn->log, XQC_LOG_ERROR, 
                            "|read unknown stream type:%d |", h3_stream->h3_stream_type);
            break;
        default:
            xqc_log(h3_conn->log, XQC_LOG_ERROR, 
                            "|read error stream type:%d |", h3_stream->h3_stream_type);
            return -XQC_H3_DECODE_ERROR;
    }

    if(nconsumed < 0){
        return nconsumed;
    }

    return nread + nconsumed;
}


ssize_t
xqc_http3_conn_read_control(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen)
{
    uint8_t * p = src, *end = src + srclen;
    int rv = 0;
    xqc_http3_stream_read_state * rstate = &h3_stream->read_state;
    xqc_http3_varint_read_state * rvint = &rstate->rvint;
    ssize_t nread;
    size_t nconsumed = 0;
    int busy = 0;
    size_t len;

    if (srclen == 0) {
        return 0;
    }

    for (;p < end ; ) {
        switch (rstate->state) {
            case XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE:
                nread = xqc_http3_read_varint(rvint, p, end - p);
                if (nread < 0) {
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += (size_t)nread;
                if(rvint->left){
                    return nconsumed;
                }

                rstate->fr.hd.type = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_FRAME_LENGTH;
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_FRAME_LENGTH:
                nread = xqc_http3_read_varint(rvint, p, end - p);
                if(nread < 0){
                    return -XQC_H3_DECODE_ERROR;
                }

                p += nread;
                nconsumed += (size_t)nread;

                if(rvint->left){
                    return (ssize_t)nconsumed;
                }
                rstate->left = rstate->fr.hd.length = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);

                if(!(h3_conn->flags & XQC_HTTP3_CONN_FLAG_SETTINGS_RECVED)){

                    if(rstate->fr.hd.type != XQC_HTTP3_FRAME_SETTINGS) {
                        XQC_CONN_ERR(h3_conn->conn, H3_MISSING_SETTINGS);
                        return -XQC_H3_CONTROL_ERROR; //the first frame is setting frame
                    }
                    h3_conn->flags |= XQC_HTTP3_CONN_FLAG_SETTINGS_RECVED;
                } else if (rstate->fr.hd.type == XQC_HTTP3_FRAME_SETTINGS){
                    XQC_CONN_ERR(h3_conn->conn, H3_SETTINGS_ERROR);
                    return -XQC_H3_CONTROL_ERROR; //not allowed send more than once
                }

                switch( rstate-> fr.hd.type){
                    case XQC_HTTP3_FRAME_PRIORITY:
                        //if no server
                        if(rstate->left < 3){
                            XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                            return -XQC_H3_CONTROL_DECODE_INVALID;
                        }

                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY;
                        break;
                    case XQC_HTTP3_FRAME_CANCEL_PUSH:
                        if(rstate->left == 0){
                            XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                            return -XQC_H3_CONTROL_DECODE_INVALID;
                        }
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_CANCEL_PUSH;
                        break;
                    case XQC_HTTP3_FRAME_SETTINGS:
                        if(rstate->left == 0){
                            //settings frame might has no element
                            xqc_http3_stream_read_state_clear(rstate);
                            break;
                        }
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS;
                        break;
                    case XQC_HTTP3_FRAME_GOAWAY:
                        if(rstate->left ==0){
                            XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                            return -XQC_H3_CONTROL_DECODE_INVALID;
                        }
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_GOAWAY;
                        break;
                    case XQC_HTTP3_FRAME_MAX_PUSH_ID:
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_MAX_PUSH_ID;
                        break;
                    default:
                        return -XQC_H3_CONTROL_DECODE_ERROR;
                }
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY:
                return -XQC_H3_CONTROL_DECODE_INVALID;

                break;

            case XQC_HTTP3_CTRL_STREAM_STATE_CANCEL_PUSH:
                //need check frame parse end?
                nread = xqc_http3_read_varint(rvint, p, end - p);
                if(nread < 0){
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;

                if(rvint->left){
                    return (ssize_t)nconsumed;
                }

                rstate->fr.cancel_push.push_id = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);

                xqc_http3_conn_on_cancel_push(h3_conn, &rstate->fr.cancel_push);
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS:
                //need finish
                for(; p < end; ){
                    len = (size_t)xqc_min(rstate->left, (int64_t)(end - p));
                    if(rstate->left == 0){
                        xqc_http3_stream_read_state_clear(rstate);
                        break;
                    }
                    nread = xqc_http3_read_varint(rvint, p, (end - p));
                    if(nread < 0){
                        return -XQC_H3_DECODE_ERROR;
                    }
                    p += nread;
                    nconsumed += (size_t)nread;
                    rstate->left -= nread;
                    if(rvint->left){
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_ID;
                        return (ssize_t)nconsumed;
                    }

                    rstate->fr.settings.iv[0].id = (uint64_t)rvint->acc;
                    xqc_http3_varint_read_state_clear(rvint);

                    if(rstate->left == 0){

                        XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                        return -XQC_H3_CONTROL_DECODE_INVALID;
                    }
                    len -= (size_t)nread;
                    if(len == 0){
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE;
                        break;
                    }

                    nread = xqc_http3_read_varint(rvint, p, len);
                    if(nread < 0){
                        return -XQC_H3_DECODE_ERROR;
                    }
                    p += nread;
                    nconsumed += (size_t)nread;
                    rstate->left -= nread;
                    if(rvint->left){
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE;
                        return (ssize_t)nconsumed;
                    }
                    rstate->fr.settings.iv[0].value = (uint64_t)rvint->acc;
                    xqc_http3_varint_read_state_clear(rvint);

                    rv = xqc_h3_conn_on_settings_entry_received( h3_conn, &rstate->fr.settings.iv[0]);
                    if (rv != 0){
                        return rv;
                    }
                }
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_ID:
                len = xqc_min(rstate->left, (end - p));
                if (len == 0) {
                    return -XQC_H3_CONTROL_DECODE_INVALID;
                }
                nread = xqc_http3_read_varint(rvint, p, len);
                if (nread < 0) {
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;
                if (rvint->left) {
                    return nconsumed;
                }
                rstate->fr.settings.iv[0].id = (uint64_t)rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);

                if (rstate->left == 0) {
                    XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                    return -XQC_H3_CONTROL_DECODE_INVALID;
                }

                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE;
                if (p == end) {
                    return (ssize_t)nconsumed;
                }
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE:
                len = xqc_min(rstate->left, (end - p));
                if (len == 0) {

                    XQC_CONN_ERR(h3_conn->conn, H3_FRAME_ERROR);
                    return -XQC_H3_DECODE_ERROR;
                }
                nread = xqc_http3_read_varint(rvint, p, len);
                if (nread < 0) {
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;
                if (rvint->left) {
                    return (ssize_t)nconsumed;
                }
                rstate->fr.settings.iv[0].value = (uint64_t)rvint->acc;

                xqc_http3_varint_read_state_clear(rvint);
                rv = xqc_h3_conn_on_settings_entry_received(h3_conn, &rstate->fr.settings.iv[0]);
                if (rv != 0) {
                    return rv;
                }
                if (rstate->left) {
                    rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS;
                    break;
                }
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_GOAWAY:
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_IGN_FRAME;
                //goaway 逻辑
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_MAX_PUSH_ID:
            {
                len = xqc_min(rstate->left, (int64_t)(end - p));
                nread = xqc_http3_read_varint(rvint, p, len);
                if (nread < 0) {
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;

                if (rvint->left) {
                    return (ssize_t)nconsumed;
                }

                uint64_t push_id = (uint64_t)rvint->acc;
                rv = xqc_http3_conn_on_max_push_id(h3_conn, push_id);
                if (rv != 0) {
                    return rv;
                }
                xqc_http3_varint_read_state_clear(rvint);
                xqc_http3_stream_read_state_clear(rstate);

                break;
            }
            case XQC_HTTP3_CTRL_STREAM_STATE_IGN_FRAME:
                //need finish
                len = xqc_min(rstate->left, end - p);
                p += len;
                nconsumed += len;
                rstate->left -= (int64_t)len;
                if (rstate->left) {
                    return (size_t)nconsumed;
                }
                xqc_http3_stream_read_state_clear(rstate);
                break;
            default:
                return -XQC_H3_CONTROL_DECODE_ERROR;
        }

    }

    return (ssize_t)nconsumed;
}

int xqc_http3_conn_on_stream_push_id(xqc_h3_conn_t *conn, xqc_h3_stream_t *stream, int64_t push_id) {

    return 0;
}

ssize_t xqc_http3_conn_read_push(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, uint8_t fin){
    return 0;
}

int xqc_http3_handle_body_data_completed(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream){

    return 0;
}

int xqc_http3_conn_call_begin_headers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream){

    return 0;
}

int xqc_http3_conn_call_begin_trailers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream){

    return 0;
}


int xqc_http3_conn_on_push_promise_push_id(xqc_h3_conn_t *h3_conn, uint64_t push_id, xqc_h3_stream_t *h3_stream){

    return 0;
}

int xqc_http3_handle_recv_data_buf(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream){

    xqc_list_head_t * head = &h3_stream->recv_data_buf;
    xqc_list_head_t *pos, *next;
    xqc_data_buf_t * data_buf = NULL;
    int ret = 1;
    xqc_http3_qpack_decoder * decoder = &h3_conn->qdec;
    xqc_http3_qpack_stream_context *sctx = &h3_stream->qpack_sctx;

    xqc_qpack_name_value_t nv={NULL,NULL,0};

    xqc_h3_request_t * h3_request = h3_stream ->h3_request ;
    xqc_http_headers_t * headers = &h3_request->h3_header.headers[h3_request->h3_header.writing_cursor];

    xqc_list_for_each_safe(pos, next, head){
        data_buf = xqc_list_entry(pos, xqc_data_buf_t, list_head);

        char * start = data_buf->data + data_buf->already_consume;
        char * end = data_buf->data + data_buf->data_len;
        ssize_t data_size = (end - start);

        ssize_t processed = xqc_http3_conn_read_bidi(h3_conn, h3_stream, start, data_size, data_buf->fin_flag );
        if(processed < 0){
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error|%z|", processed);
            XQC_H3_CONN_ERR(h3_conn, H3_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
            return -XQC_H3_EPROC_REQUEST;
        }
        if(processed == data_size){ //read data completely
            xqc_list_del(pos);
            xqc_free(data_buf);
        }else if(processed < data_size){//read part of data when blocked
            if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){
                data_buf->already_consume += processed;
                break;
            }else{
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error, read data not completely");
                XQC_H3_CONN_ERR(h3_conn, H3_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
                return -XQC_H3_EPROC_REQUEST;
            }
        }else{
            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_conn_read_bidi error, decode http3 data error");
            XQC_H3_CONN_ERR(h3_conn, H3_FRAME_ERROR, -XQC_H3_EPROC_REQUEST);
            return -XQC_H3_EPROC_REQUEST;
        }
    }

    return 0;
}


ssize_t xqc_http3_conn_read_bidi(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, uint8_t fin){

    if(srclen == 0){ //recv 0 length data
        if(fin){ //空fin
            xqc_buf_to_tail(&h3_stream->recv_body_data_buf, src, 0, fin ); //空fin是通过增加一个带fin标志的空body数据块，来通知调用层读取
        }
        return 0;
    }
    if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){
        return 0; //when blocked, read 0 length
    }

    uint8_t *p = src, *end = src + srclen;
    if (h3_stream->rx_http_state == XQC_HTTP3_HTTP_STATE_NONE){
        h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_BEGIN;
    }

    xqc_http3_stream_read_state *rstate = &h3_stream->read_state;

    xqc_http3_varint_read_state *rvint = &rstate->rvint;
    ssize_t nconsumed = 0, nread = 0;

    int len = 0, rv = 0;
    int fin_flag = 0;

    for(; p != end ;){

        switch(rstate -> state){

            case XQC_HTTP3_REQ_STREAM_STATE_FRAME_TYPE:
                nread = xqc_http3_read_varint(rvint, p, (end - p));
                if(nread < 0){
                    xqc_log(h3_conn->log, XQC_LOG_ERROR, "|read frame type error, r_state:%d|", rstate->state);
                    return -XQC_H3_DECODE_ERROR;
                }

                p += nread;
                nconsumed += nread;
                if(rvint->left) {
                   goto done;
                }
                rstate->fr.hd.type = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);
                rstate->state = XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH;

                break;
            case XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH:
                nread = xqc_http3_read_varint(rvint, p, (end - p));
                if(nread < 0){
                    xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_read_varint error, r_state:%d|", rstate->state);
                    return -XQC_H3_DECODE_ERROR;
                }
                p += nread;
                nconsumed += nread;
                if(rvint->left) {
                   goto done;
                }
                rstate->left = rvint->acc; //该frame剩余需要读取的数据长度
                rstate->fr.hd.length = rvint->acc;//frame的长度

                xqc_http3_varint_read_state_clear(rvint);

                switch(rstate->fr.hd.type){
                    case XQC_HTTP3_FRAME_HEADERS:
                        rv = xqc_http3_stream_check_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_HEADERS);
                        if(rv != 0){
                            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_stream_check_rx_http_state error ,r_state:%d, event:%d|", rstate->state, XQC_HTTP3_HTTP_EVENT_HEADERS);
                            return rv;
                        }
                        if(rstate->left == 0){ //header frame length is 0

                            rv = xqc_http3_stream_empty_headers_allowed(h3_stream);//only trailer can write
                            if(rv != 0){
                                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_stream_empty_headers_allowed error, header frame length:%d ,r_state:%d|", rstate->left, rstate->state);
                                return rv;
                            }

                            xqc_http3_stream_read_state_clear(rstate);
                            break;
                        }

                        h3_stream->header_recvd += rstate->left;
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_HEADERS;
                        break;

                    case XQC_HTTP3_FRAME_DATA:
                        rv = xqc_http3_stream_check_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_DATA); //修改成适合我们的状态机
                        if(rv != 0){
                            xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_stream_check_rx_http_state error, r_state:%d|", rstate->state);
                            return rv;
                        }
                        if(rstate->left == 0){
                            //data frame empty

                            if(fin){
                                xqc_buf_to_tail(&h3_stream->recv_body_data_buf, p, 0, fin );
                            }
                            xqc_http3_stream_read_state_clear(rstate);
                            break;
                        }
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_DATA;
                        break;
                    case XQC_HTTP3_FRAME_PUSH_PROMISE:
                        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|not support push promise yet|");
                        return -XQC_H3_UNSUPPORT_FRAME_TYPE;
                    case XQC_HTTP3_FRAME_DUPLICATE_PUSH:
                        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|not support duplicate push yet|");
                        return  -XQC_H3_UNSUPPORT_FRAME_TYPE;
                    default:
                        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|r_state:%d, rstate->fr.hd.type:%i|", rstate->state, rstate->fr.hd.type);
                        return -XQC_H3_INVALID_FRAME_TYPE;
                }
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_HEADERS:
                len = xqc_min(rstate->left, (int64_t)(end - p));

                fin_flag = XQC_HTTP3_NO_FIN;
                if(fin && (len == (end - p))){ //means stream fin, only has header data
                    fin_flag |= XQC_HTTP3_STREAM_FIN;
                }
                if(len == rstate->left){
                    fin_flag |= XQC_HTTP3_FRAME_FIN;
                }

                nread = xqc_h3_handle_header_data_streaming(h3_conn, h3_stream, p, len, fin_flag);

                if(nread < 0){
                    xqc_log(h3_conn->log, XQC_LOG_ERROR, "|r_state:%d|", rstate->state);
                    return nread;
                }

                p += nread;
                nconsumed += nread;
                rstate->left -= nread;

                if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){
                    goto blocked;
                }

                if(rstate->left){
                    goto done;
                }

                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_DATA:
                len = xqc_min(rstate->left, (int64_t)(end - p));

                if(fin && len == (end - p)){ //last frame fin data
                    fin_flag = fin;
                }else{
                    fin_flag = 0;
                }

                rv = xqc_buf_to_tail(&h3_stream->recv_body_data_buf, p, len, fin_flag);
                if(rv != 0){
                    return rv;
                }
                p += len;
                nconsumed += len;
                rstate->left -=(int64_t)len;

                if(rstate->left){
                    goto done;
                }

                rv = xqc_http3_handle_body_data_completed(h3_conn, h3_stream);
                if(rv < 0){
                    xqc_log(h3_conn->log, XQC_LOG_ERROR, "|r_state:%d|", rstate->state);
                    return rv;
                }
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID:
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|not support push promise push id yet|");
                return -XQC_H3_UNSUPPORT_FRAME_TYPE;
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE:
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|not support push promise yet|");
                return -XQC_H3_UNSUPPORT_FRAME_TYPE;
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH:
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|not support duplicate push yet|");
                return -XQC_H3_UNSUPPORT_FRAME_TYPE;
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_IGN_FRAME: //for reserve type
                len = xqc_min(rstate->left, (int64_t)(end - p));
                p += len;
                nconsumed += len;
                rstate->left -= (int64_t)len;

                if(rstate->left){
                    goto done;
                }
                xqc_http3_stream_read_state_clear(rstate);
                break;
            default:
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|r_state:%d|", rstate->state);
                return -XQC_H3_DECODE_ERROR;
        }
    }
blocked:
done:
    return (ssize_t)nconsumed;

}


int xqc_http3_http_on_remote_end_stream(xqc_h3_stream_t * h3_stream){

    //close stream
    return 0;
}

int xqc_http3_stream_check_rx_http_state(xqc_h3_stream_t * stream, xqc_http3_stream_http_event event){ //修改两个header的场景

    int rv;
    switch(stream->rx_http_state){
         case XQC_HTTP3_HTTP_STATE_NONE:
            return -XQC_H3_STATE_ERROR;
        case XQC_HTTP3_HTTP_STATE_BEGIN:
            switch(event){
                case XQC_HTTP3_HTTP_EVENT_HEADERS:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_HEADERS;
                    return 0;
                default:
                    return -XQC_H3_STATE_ERROR;
            }
            break;
        case XQC_HTTP3_HTTP_STATE_HEADERS:
            switch(event){
                case XQC_HTTP3_HTTP_EVENT_DATA:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_DATA;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_HEADERS:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_HEADERS;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_END;
                    return 0;
                default:
                    return -XQC_H3_STATE_ERROR;
            }
            break;
        case XQC_HTTP3_HTTP_STATE_DATA:
            switch(event){
                case XQC_HTTP3_HTTP_EVENT_DATA:
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_HEADERS:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_TRAILERS;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_END;
                    return 0;
                default:
                    return -XQC_H3_STATE_ERROR;
            }
            break;
        case XQC_HTTP3_HTTP_STATE_TRAILERS:
            switch(event){
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_END;
                    return 0;
                default:
                    return -XQC_H3_STATE_ERROR;
            }
            break;

        default:
            return -XQC_H3_STATE_ERROR;
    }

    return 0;
}


xqc_h3_frame_send_buf_t * 
xqc_h3_frame_create_send_buf(size_t buf_len)
{
    xqc_h3_frame_send_buf_t * p_buf = xqc_malloc(sizeof(xqc_h3_frame_send_buf_t) + buf_len);
    if(p_buf == NULL){
        return NULL;
    }

    //memset(p_buf, 0, sizeof(xqc_h3_frame_send_buf_t));
    xqc_init_list_head(&p_buf->list_head);
    p_buf->buf_len = buf_len;
    p_buf->data_len = buf_len;
    p_buf->already_consume = 0;
    p_buf->fin_flag = 0;

    return p_buf;
}

#define XQC_HTTP3_MAX_BUFFER_COUNT_SIZE (1024)
int 
xqc_h3_stream_send_buf_add(xqc_h3_stream_t * h3_stream, xqc_h3_frame_send_buf_t * send_buf)
{
    if(h3_stream->send_buf_count > XQC_HTTP3_MAX_BUFFER_COUNT_SIZE){
        return -XQC_H3_BUFFER_EXCEED;
    }

    h3_stream->send_buf_count++;

    xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);

    return XQC_OK;
}

int xqc_http3_stream_send_buf_del(xqc_h3_stream_t * h3_stream, xqc_h3_frame_send_buf_t * send_buf){
    h3_stream->send_buf_count--;
    xqc_list_del(&send_buf->list_head);
    xqc_free(send_buf);
    return 0;
}


int 
xqc_h3_uni_stream_write_stream_type(xqc_h3_stream_t * h3_stream, uint8_t stream_type)
{
    xqc_h3_frame_send_buf_t * send_buf = xqc_h3_frame_create_send_buf(1);

    if(send_buf == NULL){
        return -XQC_H3_EMALLOC;
    }
    send_buf->data[0] = stream_type;

    int ret = xqc_h3_stream_send_buf_add(h3_stream, send_buf);
    if(ret != XQC_OK){
        return ret;
    }
    return XQC_OK;
}



xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_frame_header(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len){

    xqc_http3_frame_hd hd;
    hd.type = XQC_HTTP3_FRAME_HEADERS;
    hd.length = data_len;

    int hd_len = xqc_http3_frame_write_hd_len(&hd);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf( hd_len + hd.length);
    if(send_buf == NULL){
        return send_buf;
    }

    int offset = xqc_h3_fill_frame_header(send_buf->data, hd.type, hd.length);

    if(offset < 0){
        xqc_free(send_buf);
        return NULL;
    }

    memcpy(send_buf->data+offset, data, data_len);


    return send_buf;

}




xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_frame_data(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len){

    xqc_http3_frame_hd hd;
    hd.type = XQC_HTTP3_FRAME_DATA;
    hd.length = data_len;

    int hd_len = xqc_http3_frame_write_hd_len(&hd);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf( hd_len + hd.length);
    if(send_buf == NULL){
        return send_buf;
    }

    int offset = xqc_h3_fill_frame_header(send_buf->data, hd.type, hd.length);

    if(offset < 0){
        xqc_free(send_buf);
        return NULL;
    }

    if(data_len > 0){
        memcpy(send_buf->data+offset, data, data_len);
    }

    return send_buf;

}

#define XQC_HTTP3_SEND_BUF_COMPLETE 0


/**
 * return 1 means send buf completely, return 0 means buf data send imcompletely
 */
int 
xqc_h3_send_frame_buffer(xqc_h3_stream_t * h3_stream, xqc_list_head_t * head)
{
    xqc_list_head_t *pos, *next;
    xqc_h3_frame_send_buf_t * send_buf = NULL;
    int ret = XQC_HTTP3_SEND_BUF_COMPLETE;

    xqc_list_for_each_safe(pos, next, head){
        send_buf = xqc_list_entry(pos, xqc_h3_frame_send_buf_t, list_head);

        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data + send_buf->already_consume, send_buf->data_len - send_buf->already_consume, send_buf->fin_flag );
        if (send_success == -XQC_EAGAIN ) {
            ret = -XQC_EAGAIN;
            return -XQC_EAGAIN;
        }else if(send_success < 0){
            xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_send error|ret:%z|", send_success);
            return send_success;
        }

        if(send_success + send_buf->already_consume != send_buf->data_len){
            send_buf->already_consume += send_success;
            return -XQC_EAGAIN; // means send data not completely
        }else{
            xqc_http3_stream_send_buf_del(h3_stream, send_buf);
        }

    }
    return ret;

}

int 
xqc_h3_frame_data_buffer_and_send(xqc_h3_stream_t * h3_stream, xqc_h3_frame_send_buf_t * send_buf){

    int ret = xqc_h3_stream_send_buf_add(h3_stream, send_buf);
    if(ret < 0){
        return ret;
    }

    int data_len = send_buf->data_len;
    ret = xqc_h3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf);

    if(ret == XQC_HTTP3_SEND_BUF_COMPLETE || ret == -XQC_EAGAIN ){
        return data_len;
    }else{
        return ret;
    }
}


xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_push_promise(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len, uint64_t push_id){

    xqc_http3_frame_hd hd;
    hd.type = XQC_HTTP3_FRAME_PUSH_PROMISE;
    uint64_t push_idlen = xqc_put_varint_len(push_id);
    hd.length = data_len + push_idlen;

    int hd_len = xqc_http3_frame_write_hd_len(&hd);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf( hd_len + hd.length);
    if(send_buf == NULL){
        return send_buf;
    }

    int offset = xqc_h3_fill_frame_header(send_buf->data, hd.type, hd.length);

    if(offset < 0){
        xqc_free(send_buf);
        return NULL;
    }

    char * pos = xqc_put_varint(send_buf->data + offset, push_id);
    memcpy(pos, data, data_len);


    return send_buf;

}

ssize_t xqc_http3_stream_write_push_promise(xqc_h3_stream_t * h3_stream, uint64_t push_id, char * data, ssize_t data_len, uint8_t fin){ //暂时先不支持push

    return -1;

}

ssize_t 
xqc_h3_write_headers(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, 
    xqc_http_headers_t *headers, uint8_t fin)
{
    ssize_t n_write = 0;

    xqc_http3_qpack_encoder * encoder = &h3_conn->qenc;

    n_write = xqc_h3_stream_write_header_block(h3_conn->qenc_stream, h3_stream, 
                                               encoder, headers, fin);

    if(n_write < 0){
        return n_write;
    }

    return n_write;
}

ssize_t 
xqc_h3_write_frame_header(xqc_h3_stream_t * h3_stream, 
    char * data, ssize_t data_len, uint8_t fin)
{
    if(data_len <= 0){
        return -XQC_H3_EPARAM;
    }

    int ret = 0;

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_frame_header( h3_stream, data, data_len);

    if(send_buf == NULL){
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_init_wrap_frame_header error|");
        return -XQC_H3_EMALLOC;
    }

    if(fin){
        send_buf->fin_flag = fin;
    }

    ret = xqc_h3_frame_data_buffer_and_send(h3_stream, send_buf);
    if(ret < 0){
        return ret;
    }
    return data_len;

}


ssize_t 
xqc_h3_stream_write_frame_data(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len, uint8_t fin)
{
    int ret = xqc_h3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf);

    if(ret == -XQC_EAGAIN){
        return -XQC_EAGAIN;
    }else if(ret < 0){
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|send stream buffer data error |");
        return ret;
    }

    ssize_t send_len; // send bytes every time
    ssize_t send_sum = 0; // means data send or buffer success
    ssize_t offset = 0; // means read data offset
    uint8_t fin_only = fin && data_len == 0;

    if(fin_only){

        xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_frame_data( h3_stream, data, data_len);

        send_buf->fin_flag = fin;
        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data, send_buf->data_len, send_buf->fin_flag);


        if(send_success < 0 && send_success != -XQC_EAGAIN){
            xqc_free(send_buf);
            xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|h3_stream send h3 data error,error code:%z|",send_success );
            return send_success;
        }
        if(send_success == -XQC_EAGAIN){

            ret = xqc_h3_stream_send_buf_add(h3_stream, send_buf);
            if(ret < 0){
                return ret;
            }
            return  0;
        }

        xqc_free(send_buf);
        return 0;

    }


    if(data_len <= 0){
        return -XQC_H3_EPARAM;
    }
    while(data_len > 0){
         if(data_len > XQC_MAX_FRAME_SIZE){
            send_len = XQC_MAX_FRAME_SIZE;
        }else{
            send_len = data_len;
        }

        data_len -= send_len;

        xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_frame_data( h3_stream, data+offset, send_len);

         if(send_buf == NULL){
            //log
            xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_init_wrap_frame_data error|");
            return -XQC_H3_EMALLOC;
        }

        if(fin && data_len == 0){//means last frame
            send_buf->fin_flag = fin;
        }else{
            send_buf->fin_flag = 0;
        }
        send_sum += send_len; //means data already buffer  total
        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data, send_buf->data_len, send_buf->fin_flag );

        if(send_success < 0 && send_success != -XQC_EAGAIN){
            xqc_free(send_buf);
            xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|h3_stream send h3 data error,error code:%z|",send_success );
            return send_success;
        }

        if(send_success == send_buf->data_len){
            xqc_free(send_buf);
        }else{
            if(send_success != -XQC_EAGAIN){
                send_buf->already_consume += send_success;
            }
            ret = xqc_h3_stream_send_buf_add(h3_stream, send_buf);
            if(ret < 0){
                return ret;
            }
            break;
        }

        offset += send_len;
    }

    return send_sum;

}

xqc_h3_frame_send_buf_t *
xqc_h3_init_wrap_settings(xqc_h3_stream_t *h3_stream, xqc_h3_conn_settings_t *setting)
{
    xqc_http3_frame_settings  fr_setting;

    memset(&fr_setting, 0, sizeof(xqc_http3_frame_settings));
    xqc_http3_frame_hd * hd = & fr_setting.hd;
    hd->type = XQC_HTTP3_FRAME_SETTINGS;

    size_t i = 0;
    fr_setting.niv = 0;

    if (setting->max_field_section_size) {
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_MAX_FIELD_SECTION_SIZE;
        fr_setting.iv[fr_setting.niv].value = setting->max_field_section_size;
        ++fr_setting.niv;
    }
    if (setting->qpack_max_table_capacity) {
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_QPACK_MAX_TABLE_CAPACITY;
        fr_setting.iv[fr_setting.niv].value = setting->qpack_max_table_capacity;
        ++fr_setting.niv;
    }
    if (setting->qpack_blocked_streams) {
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_QPACK_BLOCKED_STREAMS;
        fr_setting.iv[fr_setting.niv].value = setting->qpack_blocked_streams;
        ++fr_setting.niv;
    }

    int total_len = xqc_h3_frame_write_settings_len(&hd->length, &fr_setting);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf( total_len);
    if (send_buf == NULL) {
        xqc_log(h3_stream->stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_h3_frame_create_send_buf error|");
        return send_buf;
    }

    int ret = xqc_h3_frame_write_settings(send_buf->data, &fr_setting);

    if (ret != send_buf->data_len) {
        xqc_log(h3_stream->stream->stream_conn->log, XQC_LOG_ERROR,
                "|xqc_h3_frame_write_settings error|ret:%d|data_len:%uz|",
                ret, send_buf->data_len);
        xqc_free(send_buf);
        return NULL;
    }

    return send_buf;

}


int
xqc_h3_stream_write_settings(xqc_h3_stream_t *h3_stream, xqc_h3_conn_settings_t *settings)
{

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_init_wrap_settings(h3_stream, settings);

    if (send_buf == NULL) {
        xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_init_wrap_settings error|");
        return -XQC_H3_EMALLOC;
    }

    int ret = xqc_h3_frame_data_buffer_and_send(h3_stream, send_buf);
    return ret;
}


xqc_h3_frame_send_buf_t *
xqc_http3_init_wrap_cancel_push(xqc_h3_stream_t *h3_stream, xqc_http3_frame_cancel_push *fr)
{
    xqc_http3_frame_hd * hd = &fr->hd;
    hd->type =  XQC_HTTP3_FRAME_CANCEL_PUSH;

    int total_len = xqc_http3_frame_write_cancel_push_len(&hd->length, fr);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf(total_len);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_cancel_push(send_buf->data, fr);

    if(ret != send_buf->data_len){
        xqc_free(send_buf);
        return NULL;
    }

    return send_buf;
}

int xqc_http3_stream_write_cancel_push(xqc_h3_stream_t * h3_stream, xqc_http3_frame_cancel_push * fr){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_cancel_push( h3_stream, fr);

    if(send_buf == 0){
        return -XQC_H3_EMALLOC;
    }
    int ret = xqc_h3_frame_data_buffer_and_send(h3_stream, send_buf);
    return ret;
}

xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_max_push_id(xqc_h3_stream_t * h3_stream, xqc_http3_frame_max_push_id * fr){
    xqc_http3_frame_hd * hd = &fr->hd;
    hd->type =  XQC_HTTP3_FRAME_CANCEL_PUSH;

    int total_len = xqc_http3_frame_write_max_push_id_len(&hd->length, fr);

    xqc_h3_frame_send_buf_t *send_buf = xqc_h3_frame_create_send_buf(total_len);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_max_push_id(send_buf->data, fr);

    if(ret != send_buf->data_len){
        xqc_free(send_buf);
        return NULL;
    }

    return send_buf;
}

int xqc_http3_stream_write_max_push_id(xqc_h3_stream_t * h3_stream, xqc_http3_frame_max_push_id * fr){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_max_push_id( h3_stream, fr);

    if(send_buf == 0){
        return -XQC_H3_EMALLOC;
    }

    int ret = xqc_h3_frame_data_buffer_and_send(h3_stream, send_buf);
    return ret;

}


xqc_h3_stream_t * xqc_http3_find_stream(xqc_h3_conn_t * h3_conn, uint64_t stream_id){

    xqc_connection_t * conn = h3_conn->conn;
    xqc_id_hash_table_t *streams_hash = conn->streams_hash;

    xqc_stream_t *stream = xqc_id_hash_find(streams_hash, stream_id);
    if(stream == NULL){
        return NULL;
    }

    return (xqc_h3_stream_t *)(stream->user_data);
}

int xqc_http3_conn_on_cancel_push(xqc_h3_conn_t * conn, xqc_http3_frame_cancel_push * fr){


    return 0;
}

int 
xqc_h3_conn_on_settings_entry_received(xqc_h3_conn_t * conn, xqc_http3_settings_entry * iv){

    switch (iv->id) {
        case XQC_HTTP3_SETTINGS_ID_MAX_FIELD_SECTION_SIZE:
            if (conn->peer_h3_conn_settings.max_field_section_size == XQC_H3_SETTINGS_UNSET) {
                conn->peer_h3_conn_settings.max_field_section_size = iv->value;
            }
            break;
        case XQC_HTTP3_SETTINGS_ID_QPACK_MAX_TABLE_CAPACITY:
            /* TODO */
            break;
        case XQC_HTTP3_SETTINGS_ID_QPACK_BLOCKED_STREAMS:
            /* TODO */
            break;
        default:
            /* An implementation MUST ignore the contents for any SETTINGS identifier it does not understand. */
            break;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|id:%ui|value:%ui|", iv->id, iv->value);
    return 0;
}

int xqc_http3_conn_on_max_push_id(xqc_h3_conn_t * conn, uint64_t push_id){

    return 0;
}


ssize_t 
xqc_h3_qpack_encoder_stream_send(xqc_h3_stream_t * h3_stream, 
    char * data, ssize_t data_len)
{
    if (data_len <= 0) {
        return data_len;
    }

    ssize_t send_len; // send bytes every time
    ssize_t send_sum = 0; // means data send or buffer success
    ssize_t offset = 0; // means read data offset

    xqc_h3_frame_send_buf_t * send_buf = xqc_h3_frame_create_send_buf(data_len);

    if (send_buf == NULL) {
        return -XQC_H3_EMALLOC;
    }
    memcpy(send_buf->data, data, data_len); //send raw data, no frame

    send_buf->fin_flag = 0;

    int ret = xqc_h3_frame_data_buffer_and_send(h3_stream, send_buf);
    if (ret < 0) {
        return ret;
    }

    return data_len;
}

uint64_t
xqc_h3_uncompressed_fields_size(xqc_http_headers_t *headers) {
    uint64_t fields_size = 0;
    for (int i = 0; i < headers->count; i++) {
        fields_size += headers->headers[i].name.iov_len + headers->headers[i].value.iov_len + 32;
    }
    return fields_size;
}


