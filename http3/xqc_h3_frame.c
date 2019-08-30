#include "xqc_h3_frame.h"

#include "transport/crypto/xqc_tls_public.h"

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

        vint->left = xqc_get_varint_len(src);
        if(rvint->left <= srclen){
            rvint->acc = xqc_get_varint(&nread, src);
            rvint->left = 0;
            return (ssize_t)nread;
        }

        rvint->acc = xqc_get_varint_fb(src); //read first byte
        nread = 1;
        ++src;
        --srclen;
        --rint->left;
    }

    n = xqc_min(rint->left, srclen);

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

    if(vint->left){
        return nread; // means variable integer not read competely
    }

    stream_type = rvint->acc;
    xqc_http3_varint_read_state_clear(rvint);

    switch(stream_type){
        case XQC_HTTP3_STREAM_TYPE_CONTROL:
            if (conn->flags & XQC_HTTP3_CONN_FLAG_CONTROL_OPENED) {
                //xqc_log
                return -1;
            }
            conn->flags |= XQC_HTTP3_CONN_FLAG_CONTROL_OPENED;
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

    return 0;
}


ssize_t xqc_http3_conn_read_control(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){

    return 0;
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
            nconsumed = xqc_http3_conn_read_push(h3_conn, &push_nproc, h3_stream, src, srclen);
            break;
        default:
            return -1;
    }
    return nconsumed;
}


ssize_t xqc_http3_conn_read_bidi(xqc_h3_conn_t * h3_conn, size_t *pnproc, xqc_h3_stream_t * h3_stream, uint8_t *src, size_t srclen){

    if(srclen == 0){
        return 0;
    }
    uint8_t *p = src, *end = src + srclen;

    ssize_t nread;
    xqc_http3_stream_read_state *rstate = &h3_stream->rstate;

    xqc_http3_varint_read_state *rvint = &rstate->rvint;
    size_t nconsumed = 0;

    for(; p != end ;){

        switch(rs_state -> state){

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
                        if(rstate->left == 0){

                            //data frame empty
                        }
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_DATA;
                        break;
                    case XQC_HTTP3_FRAME_HEADERS:
                        //need finish
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_HEADERS;
                        break;
                    case XQC_HTTP3_FRAME_PUSH_PROMISE:
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID;
                        break;
                    case XQC_HTTP3_FRAME_DUPLICATE_PUSH:
                        rstate->state = XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH;
                        break;
                    default:
                        return -1;
                }
                break;
            case XQC_HTTP3_REQ_STREAM_STATE_DATA:

            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE_PUSH_ID:

            case XQC_HTTP3_REQ_STREAM_STATE_PUSH_PROMISE:
            case XQC_HTTP3_REQ_STREAM_STATE_HEADERS:
            case XQC_HTTP3_REQ_STREAM_STATE_DUPLICATE_PUSH:
            case XQC_HTTP3_REQ_STREAM_STATE_IGN_FRAME:

            default:

        }
    }
end:
    *pnproc = (p - src);
    return (ssize_t)nconsumed;

}




int xqc_http3_stream_transit_rx_http_state(xqc_h3_stream_t * h3_stream, xqc_http3_stream_http_event event){

    int rv;

    switch (stream->rx_http_state) {
        case XQC_HTTP3_HTTP_STATE_NONE:
            //return XQC_HTTP3_ERR_HTTP_INTERNAL_ERROR;
        case XQC_HTTP3_HTTP_STATE_REQ_INITIAL:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN;
                    return 0;
                default:
                    return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_HEADERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_HEADERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_HEADERS_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    /* TODO Better to check status code */
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) {
                        return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    }
                    rv = nghttp3_http_on_remote_end_stream(stream);
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
                    return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_DATA_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_DATA_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
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
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) {
                        return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    }
                    rv = nghttp3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_END;
                    return 0;
                default:
                    return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_TRAILERS_END:
            if (event != XQC_HTTP3_HTTP_EVENT_MSG_END) {
                /* TODO Should ignore unexpected frame in this state as per
                   spec. */
                return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_REQ_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_REQ_END:
            return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
        case XQC_HTTP3_HTTP_STATE_RESP_INITIAL:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN) {
                return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_HEADERS_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    if (stream->rx.http.status_code == -1) {
                        stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_HEADERS_BEGIN;
                        return 0;
                    }
                    if ((stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) &&
                            stream->rx.http.status_code / 100 == 2) {
                        return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    }
                    rv = nghttp3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
                    if (stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_EXPECT_FINAL_RESPONSE) {
                        return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
                    return 0;
                default:
                    return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_DATA_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_DATA_END:
            switch (event) {
                case XQC_HTTP3_HTTP_EVENT_DATA_BEGIN:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_DATA_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_HEADERS_BEGIN:
                    if ((stream->rx.http.flags & XQC_HTTP3_HTTP_FLAG_METH_CONNECT) &&
                            stream->rx.http.status_code / 100 == 2) {
                        return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
                    }
                    rv = nghttp3_http_on_remote_end_stream(stream);
                    if (rv != 0) {
                        return rv;
                    }
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN;
                    return 0;
                case XQC_HTTP3_HTTP_EVENT_MSG_END:
                    stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
                    return 0;
                default:
                    return XQC_HTTP3_ERR_HTTP_UNEXPECTED_FRAME;
            }
        case XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_BEGIN:
            if (event != XQC_HTTP3_HTTP_EVENT_HEADERS_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_TRAILERS_END:
            if (event != XQC_HTTP3_HTTP_EVENT_MSG_END) {
                return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
            }
            stream->rx_http_state = XQC_HTTP3_HTTP_STATE_RESP_END;
            return 0;
        case XQC_HTTP3_HTTP_STATE_RESP_END:
            return XQC_HTTP3_ERR_HTTP_GENERAL_PROTOCOL_ERROR;
        default:
            return -1;
    }

}

