#include "xqc_h3_frame.h"
#include "xqc_h3_stream.h"
#include "transport/xqc_conn.h"
#include "common/xqc_list.h"
#include "transport/crypto/xqc_tls_public.h"

int xqc_http3_stream_transit_rx_http_state(xqc_h3_stream_t * stream, xqc_http3_stream_http_event event);
ssize_t xqc_http3_conn_read_control(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen);
ssize_t xqc_http3_conn_read_push(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen);

xqc_http3_pri_elem_type xqc_http3_frame_pri_elem_type(uint8_t c) { return c >> 6; }
xqc_http3_elem_dep_type xqc_http3_frame_elem_dep_type(uint8_t c) {
    return (c >> 4) & 0x3;
}
uint8_t xqc_http3_frame_pri_exclusive(uint8_t c) { return (c & 0x8) != 0; }

static inline xqc_data_buf_t * xqc_create_data_buf(int buf_size){

    xqc_data_buf_t * p_buf = malloc(sizeof(xqc_data_buf_t) + buf_size);
    if(p_buf == NULL)return NULL;
    xqc_init_list_head(&p_buf->list_head);
    p_buf->data_len = buf_size;
    return p_buf;
}

int xqc_buf_to_tail(xqc_list_head_t * phead , char * data, int data_len){

    xqc_data_buf_t * p_buf = xqc_create_data_buf(data_len);
    if(p_buf == NULL){
        return -1;
    }

    memcpy(p_buf->data, data, data_len);

    xqc_list_add_tail(&p_buf->list_head, phead);
}


/*fill h3 frame header,return bytes that length and type need
 * return -1 if error
 */
int xqc_http3_fill_frame_header(char * buf, uint64_t length, uint64_t type){

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


ssize_t xqc_http3_frame_write_settings_len(int64_t *ppayloadlen, xqc_http3_frame_settings * fr){

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

int xqc_http3_frame_write_settings(uint8_t * buf,  xqc_http3_frame_settings * fr){

    int nwrite = 0;

    if(fr->niv > MAX_SETTING_ENTRY){
        return -1;
    }

    nwrite = xqc_http3_fill_frame_header(buf, fr->hd.type, fr->hd.length);
    if(nwrite < 0){
        return -1;
    }

    uint8_t * cur_buf = buf + nwrite;
    int i = 0;
    for (i = 0; i < fr->niv; ++i) {
        cur_buf = xqc_put_varint(cur_buf, (int64_t)fr->iv[i].id);
        if(cur_buf == NULL){
            return -1;
        }
        cur_buf = xqc_put_varint(cur_buf, (int64_t)fr->iv[i].value);
        if(cur_buf == NULL){
            return -1;
        }
    }

    return (cur_buf - buf);

}



size_t xqc_http3_frame_write_priority_len(int64_t * ppayloadlen, xqc_http3_frame_priority * fr){

    size_t payloadlen = 2 + xqc_put_varint_len(fr->pri_elem_id);

    switch(fr->dt){
        case XQC_HTTP3_ELEM_DEP_TYPE_REQUEST:
        case XQC_HTTP3_ELEM_DEP_TYPE_PUSH:
        case XQC_HTTP3_ELEM_DEP_TYPE_PLACEHOLDER:
            payloadlen += xqc_put_varint_len(fr->elem_dep_id);
            break;
        case XQC_HTTP3_ELEM_DEP_TYPE_ROOT:
            break;
    }
    *ppayloadlen = (int64_t)payloadlen;
    return xqc_put_varint_len(XQC_HTTP3_FRAME_PRIORITY) + xqc_put_varint_len((int64_t)payloadlen) + payloadlen;
}

int xqc_http3_frame_write_priority(uint8_t * buf, xqc_http3_frame_priority * fr){
    int nwrite = 0;
    nwrite = xqc_http3_fill_frame_header(buf, fr->hd.type, fr->hd.length);

    if(nwrite < 0){
        return -1;
    }

    uint8_t * cur_buf = buf + nwrite;

    *cur_buf++ = (uint8_t)((fr->pt <<6) | (fr->dt << 4) | (uint8_t)((fr->exclusive & 0x1) << 3));
    cur_buf = xqc_put_varint(cur_buf, fr->pri_elem_id);
    if(fr->dt != XQC_HTTP3_ELEM_DEP_TYPE_ROOT){
        cur_buf = xqc_put_varint(cur_buf, fr->elem_dep_id);
    }
    *cur_buf++ = (uint8_t)(fr->weight - 1);

    return (cur_buf - buf);

}


int xqc_http3_frame_write_hd_len( xqc_http3_frame_hd *hd){

    return xqc_put_varint_len(hd->type) + xqc_put_varint_len(hd->length);
}

int xqc_http3_frame_write_push_promise(){

    //need finish
}

int xqc_http3_frame_write_cancel_push_len(int64_t * ppayloadlen, xqc_http3_frame_cancel_push * fr){

    size_t payloadlen = xqc_put_varint_len(fr->push_id);

    *ppayloadlen = (int64_t) payloadlen;

    return xqc_put_varint_len(XQC_HTTP3_FRAME_CANCEL_PUSH) + xqc_put_varint_len( (uint64_t)payloadlen) + payloadlen;
}

int xqc_http3_frame_write_cancel_push( uint8_t * buf, xqc_http3_frame_cancel_push * fr){

    int nwrite = 0;
    nwrite = xqc_http3_fill_frame_header(buf, fr->hd.type, fr->hd.length);

    if(nwrite < 0){
        return -1;
    }

    uint8_t * cur_buf = buf + nwrite;

    cur_buf = xqc_put_varint(cur_buf, fr->push_id);

    return (cur_buf - buf);

}

int xqc_http3_frame_write_data(uint8_t * buf, uint8_t * data, int data_len){

    //need finish
}

int xqc_http3_frame_write_max_push_id_len(int64_t * ppayloadlen, xqc_http3_frame_max_push_id * fr){
    size_t payloadlen = xqc_put_varint_len(fr->push_id);

    *ppayloadlen = (int64_t) payloadlen;

    return xqc_put_varint_len(XQC_HTTP3_FRAME_MAX_PUSH_ID) + xqc_put_varint_len((int64_t)payloadlen) + payloadlen;

}

int xqc_http3_frame_write_max_push_id(uint8_t * buf, xqc_http3_frame_max_push_id *fr){
    int nwrite = 0;
    nwrite = xqc_http3_fill_frame_header(buf, fr->hd.type, fr->hd.length);

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

    if(srclen <= 0){
        return -1;
    }

    if(rvint->left == 0){

        if(rvint->acc != 0){
            return -1;
        }

        rvint->left = xqc_get_varint_len(src);
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

    if(srclen == 0){
        return -1;
    }

    nread = xqc_http3_read_varint(rvint, src, srclen);

    if(nread < 0){
        return -1;
    }

    if(rvint->left){
        return nread; // means variable integer not read competely
    }

    stream_type = rvint->acc;
    xqc_http3_varint_read_state_clear(rvint);

    switch(stream_type){
        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            if (h3_conn->flags & XQC_HTTP3_CONN_FLAG_CONTROL_OPENED) {
                //xqc_log
                return -1;
            }
            h3_conn->flags |= XQC_HTTP3_CONN_FLAG_CONTROL_OPENED;
            h3_stream->type = XQC_HTTP3_STREAM_TYPE_CONTROL;
            read_state->state = XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE;
            break;
        case XQC_HTTP3_STREAM_TYPE_PUSH:
            //if(server){return -1;}
            h3_stream->type = XQC_HTTP3_STREAM_TYPE_PUSH;
            read_state->state = XQC_HTTP3_PUSH_STREAM_STATE_PUSH_ID;
            break;
        default:
            h3_stream->type = XQC_HTTP3_STREAM_TYPE_UNKNOWN;
            break;
    }

    h3_stream->flags |= XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED;

    return nread;

}



ssize_t xqc_http3_conn_read_uni( xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, int fin){

    ssize_t nread = 0;
    ssize_t nconsumed = 0;
    size_t push_nproc;

    int rv;

#if 0
    if (h3_stream->rx_http_state == XQC_HTTP3_HTTP_STATE_NONE){

        if(h3_conn->conn.conn_type == XQC_CONN_TYPE_SERVER){
            h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_INITIAL;
            h3_stream->tx_http_state = XQC_HTTP3_HTTP_STATE_REQ_INITIAL;
        }else{
            h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_INITIAL;
            h3_stream->tx_http_state = XQC_HTTP3_HTTP_STATE_RESP_INITIAL;
        }

    }
#endif

    if(srclen == 0){
        //error
        return -1;
    }

    if(!(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)){
        nread = xqc_http3_read_control_stream_type(h3_conn, h3_stream, src, srclen);
       if(nread < 0){
            return -1;
        }
        if (!(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)){

            if(nread == srclen){
                return nread;
            }else{
                return -1;
            }
        }

        src += nread;
        srclen -= (size_t)nread;

        if(srclen == 0){
            return nread;
        }
    }

    switch(h3_stream->type){

        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            if(fin){
                return -1;
                //return XQC_HTTP3_ERR_HTTP_CLOSED_CRITICAL_STREAM;
            }
            nconsumed = xqc_http3_conn_read_control(h3_conn, h3_stream, src, srclen);
            break;
        case XQC_HTTP3_STREAM_TYPE_PUSH:
            if(fin){
                //need finish
            }
            //nconsumed = xqc_http3_conn_read_push(h3_conn, &push_nproc, h3_stream, src, srclen, fin);
            break;
        case XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER:
            if(fin){
                return -1;
            }
            //nconsumed = xqc_http3_conn_read_qpack_encoder(h3_conn, src, srclen);
            break;

        case XQC_HTTP3_STREAM_TYPE_QPACK_DECODER:
            if(fin){
                return -1;
            }
            //nconsumed = xqc_http3_conn_read_qpack_decoder(h3_conn, src, srclen);
            break;

        case XQC_HTTP3_STREAM_TYPE_UNKNOWN:
            nconsumed = (ssize_t)srclen;
            //need stop stream
            return -1;
        default:
            return -1;
    }

    if(nconsumed < 0){
        return -1;
    }

    return nread + nconsumed;
}


ssize_t xqc_http3_conn_read_control(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){
    uint8_t * p = src, *end = src + srclen;

    int rv = 0;

    xqc_http3_stream_read_state * rstate = &h3_stream->read_state;
    xqc_http3_varint_read_state * rvint = &rstate->rvint;

    ssize_t nread;
    size_t nconsumed = 0;
    int busy = 0;
    size_t len;

    if(srclen == 0){
        return -1;
    }

    for(;p !=end ; ){
        switch(rstate->state){
            case XQC_HTTP3_CTRL_STREAM_STATE_FRAME_TYPE:
                if(end - p <= 0){
                    return -1;
                }
                nread = xqc_http3_read_varint(rvint, p, end - p);
                if(nread < 0){
                    return -1;
                }
                p += nread;
                nconsumed += (size_t)nread;
                if(rvint->left){
                    goto end;
                }

                rstate->fr.hd.type = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_FRAME_LENGTH;
                if( p == end ){
                    break;
                }
            case XQC_HTTP3_CTRL_STREAM_STATE_FRAME_LENGTH:
                if(end - p <= 0){
                    return -1;
                }
                nread = xqc_http3_read_varint(rvint, p, end - p);
                if(nread < 0){
                    return -1;
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
                        //need check
                        return -1;
                    }
                    h3_conn->flags |= XQC_HTTP3_CONN_FLAG_SETTINGS_RECVED;
                } else if (rstate->fr.hd.type == XQC_HTTP3_FRAME_SETTINGS){
                    return -1;
                }

                switch( rstate-> fr.hd.type){
                    case XQC_HTTP3_FRAME_PRIORITY:
                        //if no server
                        if(rstate->left < 3){
                            return -1;
                        }

                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY;
                        break;
                    case XQC_HTTP3_FRAME_CANCEL_PUSH:
                        if(rstate->left == 0){
                            return -1;
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
                            return -1;
                        }
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_GOAWAY;
                        break;
                    case XQC_HTTP3_FRAME_MAX_PUSH_ID:
                        rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_MAX_PUSH_ID;
                        break;
                    default:
                        return -1;
                }
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY:
                switch(xqc_http3_frame_pri_elem_type(*p)){
                    case XQC_HTTP3_PRI_ELEM_TYPE_REQUEST:
                    case XQC_HTTP3_PRI_ELEM_TYPE_PUSH:
                    case XQC_HTTP3_PRI_ELEM_TYPE_PLACEHOLDER:
                        break;
                    default:
                        return -1;

                }

                rstate->fr.priority.pt = xqc_http3_frame_pri_elem_type(*p);
                rstate->fr.priority.dt = xqc_http3_frame_elem_dep_type(*p);
                rstate->fr.priority.exclusive = xqc_http3_frame_pri_exclusive(*p);
                ++p;
                ++nconsumed;
                --rstate->left;
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_PRI_ELEM_ID;
                if (p == end){
                    return nconsumed;
                }

            case XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_PRI_ELEM_ID:
                len = (size_t)xqc_min(rstate->left, (end - p));
                nread = xqc_http3_read_varint(rvint, p, end - p);

                if(nread < 0){
                    return -1;
                }

                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;


                //need finish
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_ELEM_DEP_ID;
                if( p == end){
                    return (ssize_t)nconsumed;
                 }
            case XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_ELEM_DEP_ID:
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_WEIGHT;
                if( p == end){
                    return (ssize_t)nconsumed;
                 }
            case XQC_HTTP3_CTRL_STREAM_STATE_PRIORITY_WEIGHT:
                //read priority frame competed
                xqc_http3_stream_read_state_clear(rstate);
                break;

            case XQC_HTTP3_CTRL_STREAM_STATE_CANCEL_PUSH:
                //need finish
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS:
                //need finish


                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_ID:
                //need finish
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE;
                if( p == end){
                    return (ssize_t)nconsumed;
                }
            case XQC_HTTP3_CTRL_STREAM_STATE_SETTINGS_VALUE:
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_GOAWAY:
                rstate->state = XQC_HTTP3_CTRL_STREAM_STATE_IGN_FRAME;
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_MAX_PUSH_ID:
                //need finish
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_CTRL_STREAM_STATE_IGN_FRAME:
                //need finish
                xqc_http3_stream_read_state_clear(rstate);
                break;
            default:
                return -1;
        }

    }
end:
    //*pnproc = (p - src);
    return (ssize_t)nconsumed;
}

ssize_t xqc_http3_conn_read_push(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){


    return 0;
}



ssize_t xqc_http3_conn_read_uni_frame(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen, int fin){

    ssize_t nconsumed = 0;
    size_t push_nproc;
    switch(h3_stream->type){
        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            nconsumed = xqc_http3_conn_read_control(h3_conn, h3_stream, src, srclen);
            break;
        case XQC_HTTP3_STREAM_TYPE_PUSH:
            //nconsumed = xqc_http3_conn_read_push(h3_conn, &push_nproc, h3_stream, src, srclen);
            break;
        default:
            return -1;
    }
    return nconsumed;
}

int xqc_http3_handle_header_data(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream){


    return 0;
}

int xqc_http3_handle_body_data_completed(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream){

    return 0;
}

int xqc_conn_call_begin_headers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream){

    return 0;
}

int xqc_conn_call_begin_trailers(xqc_h3_conn_t * h3_conn,xqc_h3_stream_t * h3_stream){

    return 0;
}


int xqc_http3_conn_on_push_promise_push_id(xqc_h3_conn_t *h3_conn, uint64_t push_id, xqc_h3_stream_t *h3_stream){

    return 0;
}


ssize_t xqc_http3_conn_read_bidi(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){

    if(srclen == 0){
        return 0;
    }
    uint8_t *p = src, *end = src + srclen;


    if (h3_stream->rx_http_state == XQC_HTTP3_HTTP_STATE_NONE){

        if(h3_conn->conn->conn_type == XQC_CONN_TYPE_SERVER){
            h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_INITIAL;
            h3_stream->tx_http_state = XQC_HTTP3_HTTP_STATE_REQ_INITIAL;//??
        }else{
            h3_stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_INITIAL;//??

        }

    }

    ssize_t nread;
    xqc_http3_stream_read_state *rstate = &h3_stream->read_state;

    xqc_http3_varint_read_state *rvint = &rstate->rvint;
    size_t nconsumed = 0;

    int len = 0;

    int rv = 0;
    for(; p != end ;){

        switch(rstate -> state){

            case XQC_HTTP3_REQ_STREAM_STATE_FRAME_TYPE:
                nread = xqc_http3_read_varint(rvint, p, (end - p));
                if(nread < 0){
                    return -1;
                }

                p += nread;
                nconsumed += nread;
                if(rvint->left) {
                   goto end;
                }
                rstate->fr.hd.type =  rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);
                rstate->state = XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH;

                if(p == end){
                    goto end;
                }
            case XQC_HTTP3_REQ_STREAM_STATE_FRAME_LENGTH:
                nread = xqc_http3_read_varint(rvint, p, (end - p));
                if(nread < 0){
                    return -1;
                }
                p += nread;
                nconsumed += nread;
                if(rvint->left) {

                   goto end;
                }
                rstate->left = rstate->fr.hd.length = rvint->acc;

                xqc_http3_varint_read_state_clear(rvint);

                switch(rstate->fr.hd.type){
                    case XQC_HTTP3_FRAME_DATA:
                        rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_DATA_BEGIN);
                        if(rv != 0){
                            return rv;
                        }
                        if(rstate->left == 0){
                            //data frame empty
                            rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_DATA_END);
                            if(rv != 0){
                                return rv;
                            }
                            xqc_http3_stream_read_state_clear(rstate);
                            break;
                        }
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_DATA;
                        break;
                    case XQC_HTTP3_FRAME_HEADERS:
                        //need finish
                        rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN);
                        if(rv != 0){
                            return rv;
                        }

                        if(rstate->left == 0){
#if 0
                            rv = xqc_http3_stream_empty_headers_allowed(h3_stream);
                            if(rv != 0){
                                return rv;
                            }
#endif
                            rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_HEADERS_END);
                            if(rv != 0){
                                return rv;
                            }
                            xqc_http3_stream_read_state_clear(rstate);
                            break;
                        }

                        switch(h3_stream->rx_http_state){
                            case XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN:
                            case XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN:
                                rv = xqc_conn_call_begin_headers(h3_conn, h3_stream); // need finish
                                break;
                            case XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN:
                            case XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN:
                                rv = xqc_conn_call_begin_trailers(h3_conn, h3_stream);
                                break;
                            default:
                                return -1;
                        }
                        if(rv != 0){
                            return rv;
                        }
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_HEADERS;
                        break;
                    case XQC_HTTP3_FRAME_PUSH_PROMISE:
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID;
                        break;
                    case XQC_HTTP3_FRAME_DUPLICATE_PUSH:
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH;
                        break;
                    default:
                        //control type return -1
                        return -1;
                }
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_DATA:
                len = xqc_min(rstate->left, (int64_t)(end - p));
                //rv = xqc_http3_conn_on_data(conn, h3_stream, p , len);
                rv = xqc_buf_to_tail(&h3_stream->recv_body_data_buf, p , len);
                if(rv != 0){
                    return rv;
                }
                p += len;
                rstate->left -=(int64_t)len;

                if(rstate->left){
                    goto end;
                }

                rv = xqc_http3_handle_body_data_completed(h3_conn, h3_stream);
                if(rv < 0){
                    return rv;
                }
                rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_DATA_END);
                if(rv != 0){
                    return rv;
                }
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID:
                len = xqc_min(rstate->left, (int64_t)(end -p));

                nread = xqc_http3_read_varint(rvint, p, (end - p));
                if(nread < 0){
                    return -1;
                }
                p += nread;
                nconsumed += (size_t)nread;
                rstate->left -= nread;
                if(rvint->left){
                    goto end;
                }

                rstate->fr.push_promise.push_id = rvint->acc;
                xqc_http3_varint_read_state_clear(rvint);

                if(rstate->left == 0){
                    return -1;
                }

                rv = xqc_http3_conn_on_push_promise_push_id(h3_conn, rstate->fr.push_promise.push_id, h3_stream);
                if(rv != 0){
                    return rv;
                }
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE:
                //need finish
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_HEADERS:
                len = xqc_min(rstate->left, (int64_t)(end - p));

                rv = xqc_buf_to_tail(&h3_stream->recv_header_data_buf, p, len);
                if(rv < 0){
                    return rv;
                }
                p += len;
                rstate->left -=(int64_t)len;
                if(rstate->left){
                    goto end;
                }

                rv = xqc_http3_handle_header_data(h3_conn, h3_stream);
                if(rv < 0){
                    return rv;
                }
                rv = xqc_http3_stream_transit_rx_http_state(h3_stream, XQC_HTTP3_HTTP_EVENT_HEADERS_END);
                xqc_http3_stream_read_state_clear(rstate);
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH:
            case XQC_HTTP3_REQ_STREAM_STATE_IGN_FRAME:
                //need finish
                len = xqc_min(rstate->left, (int64_t)(end - p));
                p += len;
                nconsumed += len;
                rstate->left -= (int64_t)len;

                if(rstate->left){
                    goto end;
                }

                xqc_http3_stream_read_state_clear(rstate);
                break;
            default:
                return -1;

        }
    }
end:
    *pnproc = (p - src);
    return (ssize_t)nconsumed;

}


int xqc_http3_http_on_remote_end_stream(xqc_h3_stream_t * h3_stream){

    //close stream
    return 0;
}

int xqc_http3_stream_transit_rx_http_state(xqc_h3_stream_t * stream, xqc_http3_stream_http_event event){

    int rv;

    switch (stream->rx_http_state) {
        case XQC_HTTP3_HTTP_STATE_NONE:
            //return XQC_HTTP3_ERR_HTTP_INTERNAL_ERROR;
            return -1;
        case XQC_HTTP3_HTTP_STATE_REQ_INITIAL:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN;
                    return 0;
                default:
                    return -1;
                    //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                return -1;
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_HEADERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_HEADERS_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    /* TODO Better to check status code */
#if 0
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) {
                        //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                        return -1;
                    }
#endif
                    rv = xqc_http3_http_on_remote_end_stream(stream);//close stream?
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_END;
                    return 0;
                default:
                    //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    return -1;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_DATA_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_DATA_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_DATA_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_DATA_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    /* TODO Better to check status code */
#if 0
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) {
                        //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                        return -1;
                    }
#endif
                    rv = xqc_http3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_END;
                    return 0;
                default:
                    return -1;
                    //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_END:
            if (event != XQC_HTTP3_HTTP_EVENT_MSG_END) {
                /* TODO Should ignore unexpected frame in this state as per
                   spec. */
                //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_END:
            //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            return -1;
        case XQC_HTTP3_HTTP_STATE_RESP_INITIAL:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN) {
                //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_HEADERS_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
#if 0
                    if (stream->rx.http.status_code == -1) {
                        stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN;
                        return 0;
                    }
                    if ((stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) &&
                            stream->rx.http.status_code / 100 == 2) {
                        //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                        return -1;
                    }
#endif
                    rv = xqc_http3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
#if 0
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_EXPECT_FINAL_RESPONSE) {
                        //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                        return -1;
                    }
#endif
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
                    return 0;
                default:
                    //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    return -1;
            }
        case XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_DATA_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_DATA_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
#if 0
                    if ((stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) &&
                            stream->rx.http.status_code / 100 == 2) {
                        //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                        return -1;
                    }
#endif
                    rv = xqc_http3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
                    return 0;
                default:
                    //return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    return -1;
            }
        case XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_END:
            if (event != XQC_HTTP3_HTTP_EVENT_MSG_END) {
                //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
                return -1;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_END:
            return -1;
            //return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
        default:
            return -1;
    }

}

xqc_h3_frame_send_buf_t * xqc_create_h3_frame_send_buf(size_t buf_len){

    xqc_h3_frame_send_buf_t * p_buf = malloc(sizeof(xqc_h3_frame_send_buf_t) + buf_len);
    if(p_buf == NULL){
        return NULL;
    }

    xqc_init_list_head(&p_buf->list_head);
    p_buf->buf_len = buf_len;
    p_buf->data_len = buf_len;
    p_buf->already_consume = 0;

    return p_buf;
}


xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_frame_data(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len){

    xqc_http3_frame_hd hd;
    hd.type = XQC_HTTP3_FRAME_DATA;
    hd.length = data_len;

    int hd_len = xqc_http3_frame_write_hd_len(&hd);

    xqc_h3_frame_send_buf_t *send_buf = xqc_create_h3_frame_send_buf( hd_len + hd.length);
    if(send_buf == NULL){
        return send_buf;
    }

    int offset = xqc_http3_fill_frame_header(send_buf->data, hd.type, hd.length);

    if(offset < 0){
        free(send_buf);
        return NULL;
    }

    memcpy(send_buf->data+offset, data, data_len);


    return send_buf;

}


int xqc_http3_send_frame_buffer(xqc_h3_stream_t * h3_stream, xqc_list_head_t * head){

    xqc_list_head_t *pos, *next;
    xqc_h3_frame_send_buf_t * send_buf = NULL;
    uint8_t fin = 1;
    int ret = 0;
    xqc_list_for_each_safe(pos, next, head){
        send_buf = xqc_list_entry(pos, xqc_h3_frame_send_buf_t, list_head);

        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data + send_buf->already_consume, send_buf->data_len - send_buf->already_consume, fin);

        if(send_success + send_buf->already_consume != send_buf->data_len){
            send_buf->already_consume += send_success;
            ret = 0; // means send data not completely
        }else{
            xqc_list_del(pos);
            free(pos);
        }

    }
    return ret;

}

ssize_t xqc_http3_write_frame_data(xqc_h3_stream_t * h3_stream, char * data, ssize_t data_len){

    if(data_len <= 0){
        return data_len;
    }

    ssize_t send_len; // send bytes every time
    ssize_t send_sum = 0; // means data send or buffer success
    ssize_t offset = 0; // means read data offset
    uint8_t fin = 1;


    if(xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf) != 1){
        return send_sum; //means buffer data not send completely
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
            return send_sum;
        }

        send_sum += send_len; //means data already buffer  total
        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data, send_buf->data_len, fin);

        if(send_success == send_buf->data_len){
            free(send_buf);
        }else{
            send_buf->already_consume += send_success;
            xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);
            break;
        }

        offset += send_len;
    }

    return send_sum;

}


xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_settings(xqc_h3_stream_t * h3_stream, xqc_http3_conn_settings * setting ){

    xqc_http3_frame_settings  fr_setting;

    memset(&fr_setting, 0, sizeof(xqc_http3_frame_settings));
    xqc_http3_frame_hd * hd = & fr_setting.hd;
    hd->type = XQC_HTTP3_FRAME_SETTINGS;

    size_t i = 0;
    fr_setting.niv = 0;
    if(setting->max_header_list_size){
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_MAX_HEADER_LIST_SIZE;
        fr_setting.iv[fr_setting.niv].value = setting->max_header_list_size;
        ++fr_setting.niv;
    }
    if(setting->num_placeholders){
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_NUM_PLACEHOLDERS;
        fr_setting.iv[fr_setting.niv].value = setting->num_placeholders;

        ++fr_setting.niv;
    }
    if(setting->qpack_max_table_capacity){
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_QPACK_MAX_TABLE_CAPACITY;
        fr_setting.iv[fr_setting.niv].value = setting->qpack_max_table_capacity;

        ++fr_setting.niv;

    }
    if(setting->qpack_blocked_streams){
        fr_setting.iv[fr_setting.niv].id = XQC_HTTP3_SETTINGS_ID_QPACK_BLOCKED_STREAMS;
        fr_setting.iv[fr_setting.niv].value = setting->qpack_blocked_streams;
        ++fr_setting.niv;

    }


    int hd_len = xqc_http3_frame_write_settings_len(&hd->length, &fr_setting);

    xqc_h3_frame_send_buf_t *send_buf = xqc_create_h3_frame_send_buf( hd_len + hd -> length);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_settings(send_buf->data, &fr_setting);

    if(ret != send_buf->data_len){
        free(send_buf);
        return NULL;
    }

    return send_buf;

}

int xqc_http3_stream_write_settings(xqc_h3_stream_t * h3_stream, xqc_http3_conn_settings * settings ){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_settings( h3_stream, settings);

    if(send_buf == 0){
        return -1;
    }

    xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);

    if(xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf) != 1){
        //need log
    }
    return 0;//means successful buffer
}



xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_cancel_push(xqc_h3_stream_t * h3_stream, xqc_http3_frame_cancel_push * fr){
    xqc_http3_frame_hd * hd = &fr->hd;
    hd->type =  XQC_HTTP3_FRAME_CANCEL_PUSH;

    int hd_len = xqc_http3_frame_write_cancel_push_len(&hd->length, fr);

    xqc_h3_frame_send_buf_t *send_buf = xqc_create_h3_frame_send_buf( hd_len + hd -> length);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_cancel_push(send_buf->data, fr);

    if(ret != send_buf->data_len){
        free(send_buf);
        return NULL;
    }

    return send_buf;
}

int xqc_http3_stream_write_cancel_push(xqc_h3_stream_t * h3_stream, xqc_http3_frame_cancel_push * fr){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_cancel_push( h3_stream, fr);

    if(send_buf == 0){
        return -1;
    }

    xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);

    if(xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf) != 1){
        //need log
    }
    return 0;//means successful buffer

}

xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_max_push_id(xqc_h3_stream_t * h3_stream, xqc_http3_frame_max_push_id * fr){
    xqc_http3_frame_hd * hd = &fr->hd;
    hd->type =  XQC_HTTP3_FRAME_CANCEL_PUSH;

    int hd_len = xqc_http3_frame_write_max_push_id_len(&hd->length, fr);

    xqc_h3_frame_send_buf_t *send_buf = xqc_create_h3_frame_send_buf( hd_len + hd -> length);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_max_push_id(send_buf->data, fr);

    if(ret != send_buf->data_len){
        free(send_buf);
        return NULL;
    }

    return send_buf;
}

int xqc_http3_stream_write_max_push_id(xqc_h3_stream_t * h3_stream, xqc_http3_frame_max_push_id * fr){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_max_push_id( h3_stream, fr);

    if(send_buf == 0){
        return -1;
    }

    xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);

    if(xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf) != 1){
        //need log
    }
    return 0;//means successful buffer

}



xqc_h3_frame_send_buf_t * xqc_http3_init_wrap_priority(xqc_h3_stream_t * h3_stream, xqc_http3_frame_priority * fr_priority ){

    xqc_http3_frame_hd * hd = &fr_priority->hd;
    hd->type =  XQC_HTTP3_FRAME_PRIORITY;

    int hd_len = xqc_http3_frame_write_priority_len(&hd->length, fr_priority);

    xqc_h3_frame_send_buf_t *send_buf = xqc_create_h3_frame_send_buf( hd_len + hd -> length);
    if(send_buf == NULL){
        return send_buf;
    }

    int ret = xqc_http3_frame_write_priority(send_buf->data, fr_priority);

    if(ret != send_buf->data_len){
        free(send_buf);
        return NULL;
    }

    return send_buf;
}

int xqc_http3_stream_write_priority(xqc_h3_stream_t * h3_stream, xqc_http3_frame_priority * fr_priority){

    xqc_h3_frame_send_buf_t * send_buf = xqc_http3_init_wrap_priority( h3_stream, fr_priority);

    if(send_buf == 0){
        return -1;
    }

    xqc_list_add_tail(&send_buf->list_head, &h3_stream->send_frame_data_buf);

    if(xqc_http3_send_frame_buffer(h3_stream, &h3_stream->send_frame_data_buf) != 1){
        //need log
    }
    return 0;

}

ssize_t xqc_h3_fill_outq(xqc_h3_stream_t * h3_stream, xqc_http3_frame_entry_t *fentry){

    switch(fentry->fr.hd.type){

        case XQC_HTTP3_FRAME_SETTINGS:
            break;
        case XQC_HTTP3_FRAME_PRIORITY:
            break;
        case XQC_HTTP3_FRAME_HEADERS:
            break;
        case XQC_HTTP3_FRAME_PUSH_PROMISE:
            break;
        case XQC_HTTP3_FRAME_CANCEL_PUSH:
            break;
        case XQC_HTTP3_FRAME_DATA:

            break;
        case XQC_HTTP3_FRAME_MAX_PUSH_ID:
            break;

        case XQC_HTTP3_FRAME_GOAWAY:
            break;
        default:
            break;

    }
    return 0;

}


