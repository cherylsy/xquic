#include "xqc_h3_qpack.h"
#include "xqc_h3_frame.h"
#define XQC_HTTP3_QPACK_MAX_NAMELEN 256
#include "xqc_h3_qpack_token.h"
#include "transport/xqc_conn.h"
#include "http3/xqc_h3_conn.h"
#include "transport/xqc_stream.h"
#include "common/xqc_list.h"
#include "common/xqc_hash.h"
#include "http3/xqc_h3_frame.h"
#include "http3/xqc_h3_request.h"
static size_t xqc_table_space(size_t namelen, size_t valuelen) {
    return XQC_HTTP3_QPACK_ENTRY_OVERHEAD + namelen + valuelen;
}


xqc_var_string_t * xqc_create_var_string(uint8_t * value, size_t strlen){

    xqc_var_string_t *v_str = malloc(sizeof(xqc_var_string_t) + strlen + 1);
    if(v_str == NULL){
        return NULL;
    }

    v_str->strlen = strlen;
    if(value){
        strncpy(v_str->data, value, strlen);
    }
    v_str->data[strlen] = '\0';
    return v_str;
}

int xqc_qpack_name_value_free(xqc_qpack_name_value_t *nv){

    if(nv == NULL){
        return 0;
    }
    if(nv->name){
        free(nv->name);
    }
    if(nv->value){
        free(nv->value);
    }
    return 0;
}

xqc_var_buf_t * xqc_var_buf_create(size_t capacity){

    xqc_var_buf_t * p = malloc(sizeof(xqc_var_buf_t) + capacity);
    if(p == NULL){
        return NULL;
    }
    p->capacity = capacity;
    p->used_len = 0;
    return p;
}

int xqc_var_buf_free(xqc_var_buf_t * vbuf){

    if(vbuf){
        free(vbuf);
    }
    return 0;
}

xqc_var_buf_t * xqc_var_buf_realloc( xqc_var_buf_t * src){

    size_t capacity = src->capacity * 2;
    xqc_var_buf_t *dest = xqc_var_buf_create(capacity);
    if(dest == NULL){
        return NULL;
    }
    dest->capacity = capacity;
    dest->used_len = src->used_len;
    memcpy(dest->data, src->data, src->used_len);
    free(src);
    return dest;
}

xqc_var_buf_t * xqc_var_buf_save_data(xqc_var_buf_t * buf, uint8_t *data, size_t data_len){

    xqc_var_buf_t * dest = buf;

    while(dest->used_len + data_len > dest->capacity){
        dest = xqc_var_buf_realloc(dest);
        if(dest == NULL){
            return NULL;
        }
    }

    memcpy(dest->data+dest->used_len, data, data_len);
    dest->used_len += data_len;

    return dest;
}


xqc_var_buf_t * xqc_var_buf_save_prepare(xqc_var_buf_t * buf, size_t data_len){

    xqc_var_buf_t * dest = buf;

    while(dest->used_len + data_len > dest->capacity){
        dest = xqc_var_buf_realloc(dest);
        if(dest == NULL){
            return NULL;
        }
    }

    return dest;
}

size_t xqc_http3_qpack_put_varint_len(uint64_t n, size_t prefix) {
    size_t k = (size_t)((1 << prefix) - 1);
    size_t len = 0;

    if (n < k) {
        return 1;
    }

    n -= k;
    ++len;

    for (; n >= 128; n >>= 7, ++len);

    return len + 1;
}

xqc_http3_qpack_entry * xqc_http3_qpack_context_dtable_get(xqc_http3_qpack_context *ctx, size_t absidx){
    size_t relidx;
    relidx = ctx->next_absidx - absidx - 1;
    return (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, relidx);
}


ssize_t xqc_http3_qpack_read_string(xqc_http3_qpack_read_state *rstate,
        xqc_var_buf_t ** dest, uint8_t *begin,
        uint8_t *end, int *rfin) {
    size_t len = (size_t)(end - begin);
    if(rstate->left > len){
        *rfin = 0;
        return 0;
    }else{
        *rfin = 1;
    }

    *dest = xqc_var_buf_save_data(*dest, begin, rstate->left);

    rstate->left -= rstate->left;
    return (ssize_t)rstate->left;
}

ssize_t xqc_qpack_read_string(xqc_http3_qpack_read_state *rstate,
        xqc_var_buf_t ** dest, uint8_t *begin,
        uint8_t *end) {
    size_t len = (size_t)(end - begin);
    size_t n = xqc_min(len, rstate->left);

    *dest = xqc_var_buf_save_data(*dest, begin, n);

    rstate->left -= n;
    return (ssize_t)n;
}


//read varable integer, if not complete read, should buffer until complete
ssize_t xqc_http3_qpack_read_varint(uint64_t *pdest, uint8_t *begin, uint8_t *end, size_t prefix, int *fin){

    *fin = 0;
    *pdest = 0;
    uint64_t k = (uint8_t)((1 << prefix) - 1);

    uint64_t n = 0;
    uint8_t *p = begin;
    size_t shift = 0;
    uint64_t add;

    if(((*p) & k) != k){
        *pdest = (*p) & k;   //one byte
        *fin = 1;
        return 1;
    }

    n = k;
    if(++p == end){
        *fin = 0;
        return p - begin; //not decode completely
    }

    for(; p < end; ++p, shift += 7){
        add = (*p) & 0x7f;
        if(shift > 62){
            return -1;
        }
        if((XQC_HTTP3_QPACK_INT_MAX >> shift) < add){
            return -1;//bigger than max varint
        }
        add <<= shift;
        if(XQC_HTTP3_QPACK_INT_MAX - add < n){
            return -1; //too big
        }

        n += add;

        if(((*p) & (1 << 7)) == 0){
            break;//read varint end
        }
    }

    if(p == end){
        *fin = 0;
        return (ssize_t)(p - begin);//means not decode completely
    }

    *fin = 1;
    *pdest = n;
    return (ssize_t)(p+1-begin);

}

uint8_t *xqc_http3_qpack_put_varint(uint8_t *buf, uint64_t n, size_t prefix) {
    size_t k = (size_t)((1 << prefix) - 1);

    *buf = (uint8_t)(*buf & ~k);

    if (n < k) {
        *buf = (uint8_t)(*buf | n);
        return buf + 1;
    }

    *buf = (uint8_t)(*buf | k);
    ++buf;

    n -= k;

    for (; n >= 128; n >>= 7) {
        *buf++ = (uint8_t)((1 << 7) | (n & 0x7f));
    }

    *buf++ = (uint8_t)n;

    return buf;
}


void xqc_http3_qpack_read_state_clear(xqc_http3_qpack_read_state *rstate) {
    if(rstate->name){
        xqc_var_buf_free(rstate->name);
        rstate->name = NULL;
    }
    if(rstate->value){
        xqc_var_buf_free(rstate->value);
        rstate->value = NULL;
    }
    rstate->left = 0;
    rstate->prefix = 0;
    rstate->shift = 0;
    rstate->absidx = 0;
    rstate->never = 0;
    rstate->dynamic = 0;
    rstate->huffman_encoded = 0;
}


int xqc_qpack_encoder_write_literal(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t fb,
        size_t prefix, char * name, size_t name_len, char * value, size_t value_len){

    int rv;
    size_t len;
    len = 0;
    len += (xqc_http3_qpack_put_varint_len(name_len, prefix) + name_len);
    len += (xqc_http3_qpack_put_varint_len(value_len, 7) + value_len);

    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -1;
    }

    uint8_t * p = (*pp_buf)->data + (*pp_buf)->used_len;

    *p = fb;
    p = xqc_http3_qpack_put_varint(p, name_len, prefix);
    p = xqc_cpymem(p, name, name_len);

    *p = 0;
    p = xqc_http3_qpack_put_varint(p, value_len, 7);
    p = xqc_cpymem(p, value, value_len);

    (*pp_buf)->used_len += len;
    return 0;
}



int xqc_http3_qpack_encoder_write_literal(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t flags, char *name, size_t name_len, char *value, size_t value_len){

    uint8_t fb = (uint8_t)(0x20 | ((flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX) ? 0x10 : 0));

    return xqc_qpack_encoder_write_literal(encoder, pp_buf, fb, 3, name, name_len, value, value_len);

}

#if 0
int xqc_http3_qpack_encoder_encode_nv(xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder, size_t *pmax_cnt, size_t *pmin_cnt,
        xqc_var_buf_t **pp_buf, xqc_http_header_t * header, size_t base){


    return xqc_http3_qpack_encoder_write_literal(encoder, pp_buf, header);

}
#endif

int xqc_http3_qpack_encoder_write_header_block_prefix(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t *p_buf, size_t ricnt, size_t base){

    size_t max_ents = encoder->ctx.max_table_capacity/XQC_HTTP3_QPACK_ENTRY_OVERHEAD;

    size_t encricnt =  (ricnt == 0) ? 0 : ((ricnt %(2 * max_ents))+1); //absidx means ricnt in a [abs/(2*max_ents)*(2*max_ents, (1+abs/(2*max_ents))*2*max_ents], encrint only record offset

    int sign = base < ricnt;

    size_t delta_base = sign ? (ricnt - base - 1) : (base - ricnt);
    size_t len = xqc_http3_qpack_put_varint_len(encricnt, 8) + xqc_http3_qpack_put_varint_len(delta_base, 7);

    uint8_t *p;
    int rv = 0;

    if(len > p_buf->capacity - p_buf->used_len){

        return -1;//impossible
    }

    p = p_buf->data + p_buf->used_len;

    p = xqc_http3_qpack_put_varint(p, encricnt, 8);

    if(sign){
        *p = 0x80;
    }else{
        *p = 0;
    }
    p = xqc_http3_qpack_put_varint(p, delta_base, 7);

    p_buf->used_len += len;
    return 0;

}

#if 0
int xqc_http3_send_frame_buffer(xqc_h3_stream_t * h3_stream, xqc_list_head_t * head){

    xqc_list_head_t *pos, *next;
    xqc_h3_frame_send_buf_t * send_buf = NULL;
    int ret = 1;
    xqc_list_for_each_safe(pos, next, head){
        send_buf = xqc_list_entry(pos, xqc_h3_frame_send_buf_t, list_head);

        ssize_t send_success = xqc_stream_send(h3_stream->stream, send_buf->data + send_buf->already_consume, send_buf->data_len - send_buf->already_consume, send_buf->fin);
        if (send_success < 0) {
            xqc_log(h3_stream->h3_conn->log, XQC_LOG_ERROR, "|xqc_stream_send error|ret:%i|", send_success);
            return send_success;
        }

        if(send_success + send_buf->already_consume != send_buf->data_len){
            send_buf->already_consume += send_success;
            ret = 0; // means send data not completely
            break;
        }else{
            xqc_list_del(pos);
            free(pos);
        }

    }
    return ret;

}

xqc_h3_frame_send_buf_t * xqc_create_h3_frame_send_buf(size_t buf_len){

    xqc_h3_frame_send_buf_t * p_buf = malloc(sizeof(xqc_h3_frame_send_buf_t) + buf_len);
    if(p_buf == NULL){
        return NULL;
    }

    //memset(p_buf, 0, sizeof(xqc_h3_frame_send_buf_t));
    xqc_init_list_head(&p_buf->list_head);
    p_buf->buf_len = buf_len;
    p_buf->data_len = buf_len;
    p_buf->already_consume = 0;
    p_buf->fin = 0;

    return p_buf;
}
#endif




//streaming decoder varable integer
ssize_t xqc_qpack_read_varint(int *fin, xqc_http3_qpack_read_state *rstate, uint8_t * begin, uint8_t *end){

    uint64_t k = (uint8_t)((1 << rstate->prefix) - 1); //mask
    uint64_t n = rstate->left;
    uint64_t add;
    uint8_t *p = begin;
    size_t shift = rstate->shift;

    rstate->shift = 0;
    *fin = 0;

    if(n == 0){ //first decode
        if(((*p) & k) != k){
            rstate->left = (*p) & k;
            *fin = 1; //mean varint read finish
            return 1;
        }

        n = k;
        if( ++p == end){
            rstate->left = n;
            return (ssize_t)(p - begin);
        }
    }

    for(; p != end; ++p, shift += 7){

        add = (*p) & 0x7f;
        if(shift > 62){ //shift means already read bits
            return -1;//need return error
        }
        if((XQC_HTTP3_QPACK_INT_MAX >> shift) < add){
            return -1;//bigger than max varint
        }
        add <<= shift;
        if(XQC_HTTP3_QPACK_INT_MAX - add < n){
            return -1; //too big
        }

        n += add;
        if(((*p) & (1 << 7)) == 0){
            break;//read varint end
        }

    }

    rstate->shift = shift;

    rstate->left = n;
    if(p == end){
        return (ssize_t)(p - begin);
    }

    *fin = 1; //p != end means read varint end
    return (ssize_t)(p + 1 - begin);
}

int xqc_http3_qpack_decoder_reconstruct_ricnt(xqc_http3_qpack_decoder *decoder, size_t *dest, size_t encricnt) {

    uint64_t max_ents, full, max, max_wrapped, ricnt;

    if(encricnt == 0){
        *dest = 0;
        return 0;
    }
    max_ents = decoder->ctx.max_table_capacity / XQC_HTTP3_QPACK_ENTRY_OVERHEAD;

    full = 2*max_ents;

    if(encricnt > full){
        return -1;
    }

    max = decoder->ctx.next_absidx + max_ents;

    max_wrapped =  max/full *full;

    ricnt = max_wrapped + encricnt - 1;

    if(ricnt > max){

        if(ricnt < full){
            return -1;
        }
        ricnt -= full;
    }

    *dest = ricnt;
}

void xqc_qpack_read_state_check_huffman(xqc_http3_qpack_read_state *rstate,
        const uint8_t b) {
    rstate->huffman_encoded = (b & (1 << rstate->prefix)) != 0;
}


int xqc_qpack_decoder_emit_dynamic_indexed_name(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    nv->flag = sctx->rstate.never;

    uint64_t absidx = sctx->rstate.absidx;

    xqc_http3_qpack_entry * entry;

    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, absidx);


    nv->name = xqc_create_var_string(NULL, entry->nv.name_len);
    if(nv->name == NULL){
        return -1;
    }

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, nv->name->data, entry->nv.name_len);

    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);

    if(nv->value == NULL){
        free(nv->name);
        return -1;
    }
    return 0;

}

int xqc_qpack_decoder_emit_static_indexed_name(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){
    nv->flag = sctx->rstate.never;

    int absidx = sctx->rstate.absidx;

    xqc_qpack_static_table_entry * entry = xqc_get_qpack_static_table_entry(absidx);
    if(entry == NULL){
        return -1;
    }


    nv->name = xqc_create_var_string(entry->name, entry->name_len);
    if(nv->name == NULL){
        return -1;
    }
    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);

    if(nv->value == NULL){
        free(nv->name);
        return -1;
    }

    return 0;
    //need finish
}

int xqc_http3_qpack_decoder_emit_indexed_name(xqc_http3_qpack_decoder *decoder,
        xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv) {

    if(sctx->rstate.dynamic) {

        xqc_qpack_decoder_emit_dynamic_indexed_name(decoder, sctx, nv);
    }else{

        xqc_qpack_decoder_emit_static_indexed_name(decoder, sctx, nv);
    }

}

int xqc_http3_qpack_decoder_emit_literal(xqc_http3_qpack_decoder *decoder,
        xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv) {
    nv->name = xqc_create_var_string(sctx->rstate.name->data, sctx->rstate.name->used_len );
    if(nv->name == NULL){
        return -1;
    }
    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);
    if(nv->value == NULL){
        free(nv->name);
        nv->name = NULL;
        return -1;
    }

    return 0;

}

int xqc_http3_qpack_decoder_pbrel2abs(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx){

    xqc_http3_qpack_read_state * rstate = &sctx->rstate;

    if(! rstate->dynamic){
        return -1;
    }

    rstate->absidx = rstate->left + sctx->base;
    if(rstate->absidx >= sctx->ricnt) {
        return -1;
    }

    //need check?
    return 0;
}
int xqc_http3_qpack_decoder_brel2abs(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx){

    xqc_http3_qpack_read_state * rstate = &sctx->rstate;
    if(rstate->dynamic) {

        if (sctx->base < rstate->left + 1) {

            return -1;
        }
        rstate->absidx = sctx->base - rstate->left - 1;
        if (rstate->absidx >= sctx->ricnt) {
            return -1;
        }

    }else{

        rstate->absidx = rstate->left;
    }

    //need check??

    return 0;

}

int xqc_qpack_decoder_emit_dynamic_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    nv->flag = sctx->rstate.never;

    uint64_t absidx = sctx->rstate.absidx;

    xqc_http3_qpack_entry * entry;

    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, absidx);


    nv->name = xqc_create_var_string(NULL, entry->nv.name_len);

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, nv->name->data, entry->nv.name_len);

    nv->value = xqc_create_var_string(NULL, entry->nv.value_len);

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, nv->value->data, entry->nv.value_len);

    return 0;
}

int xqc_qpack_decoder_emit_static_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    nv->flag = sctx->rstate.never;

    int absidx = sctx->rstate.absidx;

    xqc_qpack_static_table_entry * entry = xqc_get_qpack_static_table_entry(absidx);
    if(entry == NULL){
        return -1;
    }


    nv->name = xqc_create_var_string(entry->name, entry->name_len);
    if(nv->name == NULL){
        return -1;
    }
    nv->value = xqc_create_var_string(entry->value, entry->value_len);

    if(nv->value == NULL){
        free(nv->name);
        return -1;
    }

    return 0;

}

int xqc_http3_qpack_decoder_emit_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    if(sctx->rstate.dynamic) {

        return xqc_qpack_decoder_emit_dynamic_indexed(decoder, sctx, nv);
    }else{
        return xqc_qpack_decoder_emit_static_indexed(decoder, sctx, nv);

    }

}

ssize_t xqc_http3_qpack_decoder_read_request_header_buffer(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv, uint8_t *pflags, uint8_t *src, size_t srclen, int *need_more_flag) {

    uint8_t *p = src, *end = src + srclen;
    int ret = -1;

    ssize_t nread;

    int rfin;
    uint64_t vint = 0;

    *pflags = XQC_HTTP3_QPACK_DECODE_FLAG_NONE;
    *need_more_flag = 0;

    for(; p < end; ){

        switch (sctx->state){
            case XQC_HTTP3_QPACK_RS_STATE_RICNT:
                nread = xqc_http3_qpack_read_varint(&vint, p, end, 8, &rfin);
                if(nread < 0){
                    ret = -1;
                    goto fail;
                }
                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;

                ret = xqc_http3_qpack_decoder_reconstruct_ricnt(decoder, &sctx->ricnt, vint);
                if(ret != 0){
                    goto fail;
                }
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_DBASE_SIGN;
                break;

            case XQC_HTTP3_QPACK_RS_STATE_DBASE_SIGN:
                if((*p) & 0x80){
                    sctx->dbase_sign = 1;
                }

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_DBASE;

            case XQC_HTTP3_QPACK_RS_STATE_DBASE:
                nread = xqc_http3_qpack_read_varint(&vint, p, end, 7, &rfin);
                if(nread < 0){
                     ret = -1;
                    goto fail;
                }
                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;

                if(sctx->dbase_sign){//base 符号位
                    if(sctx->ricnt <  sctx->rstate.left){
                        ret = -1;
                        goto fail;
                    }
                    sctx->base = sctx->ricnt - vint - 1;
                }else{

                    sctx->base = sctx->ricnt + vint;
                }

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;

                if(sctx->ricnt >  decoder->ctx.next_absidx) {
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_BLOCKED;
                    *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED;
                    return p - src;
                }

                break;
            case XQC_HTTP3_QPACK_RS_STATE_OPCODE:
                if((*p) & 0x80){
                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED;
                    sctx->rstate.dynamic = !((*p) & 0x40);
                    sctx->rstate.prefix = 6;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else if((*p) & 0x40){

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME;
                    sctx->rstate.never = (*p) & 0x20;
                    sctx->rstate.dynamic = !((*p) & 0x10);
                    sctx->rstate.prefix = 4;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else if ((*p) & 0x20){

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_LITERAL;
                    sctx->rstate.never = (*p) & 0x10;
                    sctx->rstate.dynamic = 0;
                    sctx->rstate.prefix = 3;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_NAME_HUFFMAN;
                }else if ((*p) & 0x10){
                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_PB;
                    sctx->rstate.dynamic = 1;
                    sctx->rstate.prefix = 4;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else {

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB;
                    sctx->rstate.never = (*p) & 0x08;
                    sctx->rstate.dynamic = 1;
                    sctx->rstate.prefix = 3;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_INDEX:
                nread = xqc_http3_qpack_read_varint(&vint, p, end, sctx->rstate.prefix, &rfin);
                if(nread < 0){
                    ret = -1;
                    goto fail;
                }
                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;
                sctx->rstate.left = vint;
                switch(sctx->opcode) {
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED:
                        ret = xqc_http3_qpack_decoder_brel2abs(decoder, sctx);
                        if (ret != 0){
                            goto fail;
                        }
                        xqc_http3_qpack_decoder_emit_indexed(decoder, sctx, nv);
                        *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                        xqc_http3_qpack_read_state_clear(&sctx->rstate);
                        return p - src;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_PB:
                        ret = xqc_http3_qpack_decoder_pbrel2abs(decoder, sctx);
                        if(ret != 0){

                            goto fail;
                        }
                        xqc_http3_qpack_decoder_emit_indexed(decoder, sctx, nv);
                        *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                        xqc_http3_qpack_read_state_clear(&sctx->rstate);
                        return p - src;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                        ret = xqc_http3_qpack_decoder_brel2abs(decoder, sctx);
                        if (ret != 0) {
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        ret = xqc_http3_qpack_decoder_pbrel2abs(decoder, sctx);
                        if (ret != 0) {
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    defalut:
                        goto fail;

                }
                break;
            case XQC_HTTP3_QPACK_RS_STATE_CHECK_NAME_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&sctx->rstate, *p);
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAMELEN;
                sctx->rstate.left = 0;
            case XQC_HTTP3_QPACK_RS_STATE_READ_NAMELEN:
                nread = xqc_http3_qpack_read_varint(&vint, p, end, sctx->rstate.prefix, &rfin);
                if(nread < 0){
                    goto fail;
                }
                if(rfin == 0){

                    goto need_more_data;
                }
                p += nread;

                sctx->rstate.left = vint;
                 if (sctx->rstate.left > XQC_HTTP3_QPACK_MAX_NAMELEN) {
                    goto fail;
                }
                if(sctx->rstate.huffman_encoded) {
                    goto fail;
                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAME;
                    sctx->rstate.name = xqc_var_buf_create(sctx->rstate.left + 1);
                    if(sctx->rstate.name == NULL){
                        goto fail;
                    }
                }
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_NAME:
                nread = xqc_http3_qpack_read_string(&sctx->rstate, &sctx->rstate.name, p, end, &rfin);
                if (nread < 0) {
                    ret = (int)nread;
                    goto fail;
                }

                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                sctx->rstate.prefix = 7;
                break;

            case XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&sctx->rstate, *p);
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUELEN;

                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;

            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUELEN:
                nread = xqc_http3_qpack_read_varint(&vint, p, end, sctx->rstate.prefix, &rfin);
                if(nread < 0){
                    ret = (int)nread;
                    goto fail;
                }

                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;

                sctx->rstate.left = vint;
                if(sctx->rstate.left > XQC_HTTP3_QPACK_MAX_VALUELEN){
                    ret = -1;
                    goto fail;
                }

                if(sctx->rstate.huffman_encoded){
                    ret = -1;
                    goto fail;
                    //need finish
                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUE;
                    sctx->rstate.value = xqc_var_buf_create(sctx->rstate.left + 1);
                    if(sctx->rstate.value == NULL){
                        goto fail;
                    }

                }
            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUE:
                nread = xqc_http3_qpack_read_string(&sctx->rstate, &sctx->rstate.value, p, end, &rfin);
                if(nread < 0){
                    ret = (int)nread;
                    goto fail;
                }
                if(rfin == 0){
                    goto need_more_data;
                }
                p += nread;

                switch(sctx->opcode){
                    case XQC_HTTP3_QPACK_RS_OPCODE_LITERAL:
                        if(xqc_http3_qpack_decoder_emit_literal(decoder, sctx, nv) < 0){
                            goto fail;
                        }
                        break;

                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        xqc_http3_qpack_decoder_emit_indexed_name(decoder, sctx, nv);
                    default:
                        /* Unreachable */
                        goto fail;
                }

                *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&sctx->rstate);

                return p - src;
            default:
                goto fail;
        }

    }

need_more_data:
    *need_more_flag = 1;
    return p - src;
fail:
    return ret;

}

int xqc_qpack_decoder_block_stream_check_and_process(xqc_h3_conn_t *h3_conn, uint64_t absidx){

    xqc_qpack_decoder_block_stream_t * p_b_stream;
    xqc_list_head_t * head = &h3_conn->block_stream_head;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        p_b_stream = xqc_list_entry( pos, xqc_qpack_decoder_block_stream_t, head_list);

        if(p_b_stream->ricnt >= absidx){
            break;
        }
        xqc_list_del(pos);
        p_b_stream->h3_stream->flags &= (~XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED);
        int ret = xqc_http3_handle_header_data(h3_conn, p_b_stream->h3_stream);
        if(ret < 0){
            return ret;
        }
        free(p_b_stream);
    }


    return 0;
}

int xqc_qpack_decoder_block_stream_insert(xqc_h3_stream_t * h3_stream, uint64_t ricnt, xqc_list_head_t *head){

    xqc_qpack_decoder_block_stream_t * block_stream = malloc(sizeof(xqc_qpack_decoder_block_stream_t));

    xqc_init_list_head(&block_stream->head_list);
    block_stream->ricnt = ricnt;
    block_stream->h3_stream = h3_stream;
    block_stream->stream_id = h3_stream->stream->stream_id;

    xqc_qpack_decoder_block_stream_t * p_b_stream;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        p_b_stream = xqc_list_entry( pos, xqc_qpack_decoder_block_stream_t, head_list);
        if(p_b_stream->ricnt > block_stream->ricnt){
            break;
        }
    }

    xqc_list_add_tail(&block_stream->head_list, pos);

    return 0;
}




ssize_t xqc_http3_qpack_decoder_read_request_header(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv, uint8_t *pflags, uint8_t *src, size_t srclen, int fin) { //streaming decode

    uint8_t *p = src, *end = src + srclen;
    int ret, rv = -1;

    int rfin;
    ssize_t nread;

    *pflags = XQC_HTTP3_QPACK_DECODE_FLAG_NONE;

    for(; p < end; ){

        switch (sctx->state){

            case XQC_HTTP3_QPACK_RS_STATE_RICNT:
                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);
                if(nread < 0){
                    ret = -1;
                    goto fail;
                }
                p += nread;
                if(!rfin){

                    goto almost_ok;
                }

                rv = xqc_http3_qpack_decoder_reconstruct_ricnt(decoder, &sctx->ricnt, sctx->rstate.left);
                if(rv != 0){
                    goto fail;
                }
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_DBASE_SIGN;
                break;
            case XQC_HTTP3_QPACK_RS_STATE_DBASE_SIGN:
                if((*p) & 0x80){
                    sctx->dbase_sign = 1;
                }

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_DBASE;
                sctx->rstate.left = 0;
                sctx->rstate.prefix = 7;
                sctx->rstate.shift = 0;

            case XQC_HTTP3_QPACK_RS_STATE_DBASE:
                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);
                if(nread < 0){
                    rv = -1;
                    goto fail;
                }

                p += nread;
                if(!rfin){

                    goto almost_ok;
                }

                if(sctx->dbase_sign){//base 符号位
                    if(sctx->ricnt <  sctx->rstate.left){
                        ret = -1;
                        goto fail;
                    }
                    sctx->base = sctx->ricnt - sctx->rstate.left - 1;
                }else{

                    sctx->base = sctx->ricnt + sctx->rstate.left;
                }

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;

                if(sctx->ricnt >  decoder->ctx.next_absidx) {

                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_BLOCKED;
                    *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED;
                    return p - src;
                }

                break;
            case XQC_HTTP3_QPACK_RS_STATE_OPCODE:
                if((*p) & 0x80){
                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED;
                    sctx->rstate.dynamic = !((*p) & 0x40);
                    sctx->rstate.prefix = 6;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else if((*p) & 0x40){

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME;
                    sctx->rstate.never = (*p) & 0x20;
                    sctx->rstate.dynamic = !((*p) & 0x10);
                    sctx->rstate.prefix = 4;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else if ((*p) & 0x20){

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_LITERAL;
                    sctx->rstate.never = (*p) & 0x10;
                    sctx->rstate.dynamic = 0;
                    sctx->rstate.prefix = 3;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_NAME_HUFFMAN;
                }else if ((*p) & 0x10){
                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_PB;
                    sctx->rstate.dynamic = 1;
                    sctx->rstate.prefix = 4;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }else {

                    sctx->opcode = XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB;
                    sctx->rstate.never = (*p) & 0x08;
                    sctx->rstate.dynamic = 1;
                    sctx->rstate.prefix = 3;
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_INDEX;
                }
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_INDEX:
                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);

                if(nread < 0){

                    rv = -1;
                    goto fail;
                }

                p += nread;
                if(!rfin){

                    goto almost_ok;
                }

                switch(sctx->opcode) {
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED:
                        rv = xqc_http3_qpack_decoder_brel2abs(decoder, sctx);
                        if (rv != 0){
                            goto fail;
                        }
                        xqc_http3_qpack_decoder_emit_indexed(decoder, sctx, nv);
                        *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                        xqc_http3_qpack_read_state_clear(&sctx->rstate);
                        return p - src;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_PB:
                        rv = xqc_http3_qpack_decoder_pbrel2abs(decoder, sctx);
                        if(rv != 0){

                            goto fail;
                        }
                        xqc_http3_qpack_decoder_emit_indexed(decoder, sctx, nv);
                        *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                        xqc_http3_qpack_read_state_clear(&sctx->rstate);
                        return p - src;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                        rv = xqc_http3_qpack_decoder_brel2abs(decoder, sctx);
                        if (rv != 0) {
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        rv = xqc_http3_qpack_decoder_pbrel2abs(decoder, sctx);
                        if (rv != 0) {
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    defalut:
                        goto fail;

                }
                break;
            case XQC_HTTP3_QPACK_RS_STATE_CHECK_NAME_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&sctx->rstate, *p);
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAMELEN;
                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;
            case XQC_HTTP3_QPACK_RS_STATE_READ_NAMELEN:

                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);

                if (nread < 0) {

                    goto fail;
                }

                p += nread;
                if (!rfin) {
                    goto almost_ok;
                }
                if (sctx->rstate.left > XQC_HTTP3_QPACK_MAX_NAMELEN) {
                    goto fail;
                }
                if(sctx->rstate.huffman_encoded) {
                    goto fail;
                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAME;
                    sctx->rstate.name = xqc_var_buf_create(sctx->rstate.left + 1);
                    if(sctx->rstate.name == NULL){
                        goto fail;
                    }
                }
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_NAME:
                nread = xqc_qpack_read_string(&sctx->rstate, &sctx->rstate.name, p, end);
                if (nread < 0) {
                    rv = (int)nread;
                    goto fail;
                }

                p += nread;

                if (sctx->rstate.left) {
                    goto almost_ok;
                }

                //qpack_read_state_terminate_name(&sctx->rstate);

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                sctx->rstate.prefix = 7;
                break;


            case XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&sctx->rstate, *p);
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUELEN;

                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;

            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUELEN:
                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);
                if(nread < 0){
                    ret = (int)nread;
                    goto fail;
                }

                p += nread;
                if(!rfin){
                    goto almost_ok;
                }

                if(decoder->rstate.left > XQC_HTTP3_QPACK_MAX_VALUELEN){
                    ret = -1;
                    goto fail;
                }

                if(sctx->rstate.huffman_encoded){
                    ret = -1;
                    goto fail;
                    //need finish
                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUE;
                    sctx->rstate.value = xqc_var_buf_create(sctx->rstate.left + 1);
                    if(sctx->rstate.value == NULL){
                        goto fail;
                    }

                }

            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUE:
                nread = xqc_qpack_read_string(&sctx->rstate, &sctx->rstate.value, p, end);
                if(nread < 0){
                    ret = (int)nread;
                    goto fail;
                }

                p += nread;

                if(sctx->rstate.left){
                    goto almost_ok;
                }

                //xqc_qpack_read_state_terminate_value(&sctx->rstate);

                switch(sctx->opcode){
                    case XQC_HTTP3_QPACK_RS_OPCODE_LITERAL:
                        if(xqc_http3_qpack_decoder_emit_literal(decoder, sctx, nv) < 0){
                            goto fail;
                        }
                        break;

                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        xqc_http3_qpack_decoder_emit_indexed_name(decoder, sctx, nv);
                    default:
                        /* Unreachable */
                        goto fail;
                }

                *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&sctx->rstate);

                return p - src;
            default:
                goto fail;
        }
    }

almost_ok:
    if(fin){
        //need finished
        return -1;
    }
    return p - src;

fail:
    return rv;
}


int xqc_http3_qpack_stream_context_init(xqc_http3_qpack_stream_context *sctx, int64_t stream_id){

    memset(sctx, 0, sizeof(xqc_http3_qpack_stream_context));

    sctx->rstate.prefix = 8;
    sctx->state = XQC_HTTP3_QPACK_RS_STATE_RICNT;
    sctx->opcode = 0;
    sctx->stream_id = stream_id;
    sctx->ricnt = 0;
    sctx->dbase_sign = 0;
    sctx->base = 0;

    return 0;
}


int xqc_http3_qpack_stream_context_free(xqc_http3_qpack_stream_context * sctx){

    if(sctx == NULL){
        return 0;
    }
    //free block_list
    if(sctx->rstate.name){
        xqc_var_buf_free(sctx->rstate.name);
        sctx->rstate.name = NULL;
    }

    if(sctx->rstate.value){
        xqc_var_buf_free(sctx->rstate.value);
        sctx->rstate.value = NULL;
    }

    return 0;

}

int xqc_http3_ringdata_pop_back(xqc_http3_ringdata *rdata, xqc_http3_qpack_entry *entry){

    int ret = 0;
    ret = xqc_http3_ringdata_out_queue(rdata, entry->nv.name_index, entry->nv.name_len);
    if(ret < 0){
        return -1;
    }

    ret = xqc_http3_ringdata_out_queue(rdata, entry->nv.value_index, entry->nv.value_len);
    if(ret < 0){
        return -1;
    }
    return 0;
}



int xqc_http3_qpack_dtable_pop(xqc_http3_qpack_context *ctx){

    int i = 0;
    i = xqc_http3_ringbuf_len(&ctx->dtable);
    xqc_http3_qpack_entry * entry = (xqc_http3_qpack_entry *) xqc_http3_ringbuf_get(&ctx->dtable, i-1);

    ctx->dtable_size -= xqc_table_space(entry->nv.name_len, entry->nv.value_len);
    if(xqc_http3_ringdata_pop_back(&ctx->dtable_data, entry) < 0){
        return -1;
    }
    xqc_http3_ringbuf_pop_back(&ctx->dtable);
    xqc_list_del(&entry->head_list); //delete from hash list, if no hash list, it is safe for del
    return 0;

}


int xqc_http3_qpack_encoder_reduce_dtable_size(xqc_http3_qpack_encoder *encoder, size_t cap){

    xqc_http3_qpack_context *ctx = &encoder->ctx;
    xqc_http3_qpack_entry *ent;
    size_t i,ret;

    ctx->max_dtable_size = cap;

    uint64_t ref_idx = XQC_MAX_UINT64;
    if(xqc_list_empty(&encoder->unack_stream_head)){
        ref_idx = XQC_MAX_UINT64;
    }else{
        xqc_qpack_unack_header_block * u_hb = xqc_list_entry(encoder->unack_stream_head.next, xqc_qpack_unack_header_block, header_block_list);
        ref_idx = u_hb->min_rcnt;
    }


    while(ctx->dtable_size > cap){

        i = xqc_http3_ringbuf_len(&ctx->dtable);
        if(i == 0){
            return -1;
        }
        ent = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, i - 1);

        xqc_http3_qpack_entry * entry = (xqc_http3_qpack_entry *) xqc_http3_ringbuf_get(&ctx->dtable, xqc_http3_ringbuf_len(&ctx->dtable) -1);
        if(entry->absidx < ref_idx){ //little than means can be del
            xqc_http3_qpack_dtable_pop(ctx);
        }else{
            break;
        }

    }

    return 0;
}


int xqc_http3_qpack_encoder_expand_dtable_size(xqc_http3_qpack_encoder *encoder, size_t cap){

    xqc_http3_qpack_context *ctx = &encoder->ctx;

    xqc_http3_ringdata *rdata = &(ctx->dtable_data);
    if(rdata->capacity > cap){
        return 0; //no need expand
    }

    size_t msize = 1;
    for(; msize < cap; msize = msize << 1);

    char * buf = malloc(msize);
    size_t capacity = msize;
    size_t mask = msize - 1;



    size_t i = xqc_http3_ringbuf_len(&ctx->dtable);
    if(i == 0){
        return 0;
    }
    xqc_http3_qpack_entry *ent = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, 0);

    size_t abs_index = ent->nv.name_index;

    xqc_http3_ringdata_copy_data_to_buf(rdata, abs_index, rdata->used, buf, mask);

    free(rdata->buf);
    rdata->buf = buf;
    rdata->capacity = capacity;
    rdata->mask = mask;

    return 0;


}

int xqc_qpack_write_number(xqc_var_buf_t **pp_buf, uint8_t fb, uint64_t num, size_t prefix){

    size_t len = xqc_http3_qpack_put_varint_len(num, prefix);

    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -1;
    }

    uint8_t * p = (*pp_buf)->data + (*pp_buf)->used_len;


    *p = fb;
    p = xqc_http3_qpack_put_varint(p, num, prefix);

    (*pp_buf)->used_len += len;

    return 0;

}
int xqc_http3_qpack_encoder_write_set_dtable_cap(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, size_t cap){

    xqc_http3_qpack_context *ctx = &encoder->ctx;

    if(ctx->max_table_capacity < cap){
        return -1;
    }

    if(ctx->dtable_size < cap){
        ctx->max_dtable_size = cap;
        xqc_qpack_write_number(p_enc_buf, 0x20, cap, 5);

    }

    return 0;


}

int xqc_http3_qpack_decoder_set_dtable_cap(xqc_http3_qpack_decoder * decoder, size_t cap){ //缓存大小调整，在调整大的时候扩大缓存的实现暂未实现, 调整小时不缩小缓存的内存

    xqc_http3_qpack_entry *ent;
    size_t i,ret;
    xqc_http3_qpack_context *ctx = &decoder->ctx;

    if(cap > ctx->max_table_capacity){
        return -1;
    }

    ctx->max_dtable_size = cap;

    while(ctx->dtable_size > cap){

        i = xqc_http3_ringbuf_len(&ctx->dtable);
        ent = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, i - 1);

        /*
        //decoder how to check
        */
        ctx->dtable_size -= xqc_table_space(ent->nv.name_len, ent->nv.value_len);

        //xqc_http3_qpack_entry_free_nv(ent);
        ret = xqc_http3_ringdata_out_queue(&ctx->dtable_data, ent->nv.name_index, ent->nv.name_len);
        if(ret < 0){
            //error, should close connection
            return -1;
        }
        ret = xqc_http3_ringdata_out_queue(&ctx->dtable_data, ent->nv.value_index, ent->nv.value_len);
        if(ret < 0){
            return -1;
        }

        xqc_http3_ringbuf_pop_back(&ctx->dtable);

    }

    return 0;
}

int xqc_http3_qpack_decoder_rel2abs(xqc_http3_qpack_decoder * decoder, xqc_http3_qpack_read_state * rstate){
    if(rstate->dynamic){

        if (decoder->ctx.next_absidx < rstate->left + 1) {
            return -1;
        }
        rstate->absidx = decoder->ctx.next_absidx - rstate->left - 1;
    }else{

        rstate->absidx = rstate->left;
    }

    return 0;
}


int xqc_http3_qpack_entry_init(xqc_http3_qpack_entry *ent, size_t name_index, size_t name_len, size_t value_index, size_t value_len, size_t sum, size_t absidx){

    xqc_init_list_head(&ent->head_list);
    ent->nv.name_index = name_index;
    ent->nv.name_len = name_len;
    ent->nv.value_index = value_index;
    ent->nv.value_len = value_len;
    ent->sum = sum;
    ent->absidx = absidx;
    //ent->hash = hash;

    return 0;
}

int xqc_http3_qpack_hash_find(xqc_qpack_hash_table_t * table, xqc_http3_ringdata *rdata, char * name, size_t name_len, char *value, size_t value_len, xqc_qpack_find_result *result){

    uint64_t hash = 0;
    //xqc_qpack_find_result_init(result);
    result->name_entry = NULL;
    result->entry = NULL;
    hash = xqc_hash_string(name, name_len);

    uint32_t hash_index = hash%(table->element_count);

    xqc_list_head_t *head = &(table->list[hash_index]);

    xqc_list_head_t * pos;
    xqc_http3_qpack_entry * entry;

    xqc_list_for_each(pos, head){

        entry = xqc_list_entry(pos, xqc_http3_qpack_entry, head_list);
        if( (name_len == entry->nv.name_len &&  0 == xqc_http3_ringdata_cmp(rdata, entry->nv.name_index, name, entry->nv.name_len) ) ){
            if(result->name_entry == NULL){
                result->name_entry = entry;
            }
            if( (value_len == entry->nv.value_len) && (0 == xqc_http3_ringdata_cmp(rdata, entry->nv.value_index, value, entry->nv.value_len))){
                result->entry = entry;
                break;
            }
        }
    }

    return 0;
}

int xqc_http3_qpack_stable_find(xqc_qpack_static_find_result * s_result, int token, uint8_t * name, size_t name_len, uint8_t *value, size_t value_len){

    if(token < 0 || token >= XQC_QPACK_TOKEN_MAX_SIZE){

        return -1;
    }
    s_result->name_absidx = xqc_get_qpack_token_index_value(token);
    if(s_result->name_absidx == -1){
        s_result->absidx = -1;
        return 0;
    }

    int idx = s_result->name_absidx;
    for(; idx < xqc_get_qpack_static_table_size(); idx++){
        xqc_qpack_static_table_entry * s_entry = xqc_get_qpack_static_table_entry(idx);
        if(s_entry->name_len != name_len  || xqc_memeq(s_entry->name, name, name_len)){

            s_result->absidx = -1;
            return 0;
        }
        if(s_entry->value_len == value_len  && xqc_memeq(s_entry->value, value, value_len)){
            s_result->absidx = idx;
            return 0;
        }
    }

    s_result->absidx = -1;
    return 0;
}

int xqc_http3_qpack_hash_insert(xqc_qpack_hash_table_t * table, char *name, size_t name_len, xqc_list_head_t * head_list){

    uint64_t hash = xqc_hash_string(name, name_len);

    uint32_t hash_index = hash%(table->element_count);

    xqc_list_head_t *head = &(table->list[hash_index]);

    xqc_list_add(head_list, head);

    return 0;
}

int xqc_http3_qpack_hash_del(xqc_list_head_t * head_list){
    xqc_list_del(head_list);
    return 0;
}

int xqc_http3_qpack_context_dtable_add(xqc_http3_qpack_context *ctx, uint8_t * name, size_t name_len, uint8_t *value, size_t value_len, xqc_qpack_hash_table_t * dtable_hash){


    size_t space;
    int i,rv, ret = 0 ;
    //xqc_qpack_name_value *p_nv = &ent->nv, *nv;
    space = xqc_table_space(name_len, value_len);
    while (ctx->dtable_size + space > ctx->max_dtable_size) {
        xqc_http3_qpack_dtable_pop(ctx);
    }


    size_t name_index, value_index;
    xqc_http3_ringdata_in_queue(&ctx->dtable_data, &name_index, name, name_len);
    xqc_http3_ringdata_in_queue(&ctx->dtable_data, &value_index, value, value_len);

    xqc_http3_qpack_entry *entry = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_push_front(&ctx->dtable);
    if(entry == NULL){
        return -1;
    }
    xqc_http3_qpack_entry_init(entry, name_index, name_len, value_index, value_len,  ctx->dtable_sum, ctx->next_absidx++);

    if(dtable_hash != NULL){
        xqc_http3_qpack_hash_insert(dtable_hash, name, name_len, &entry->head_list);
    }

#if 0
    if(xqc_http3_ringbuf_full(&ctx->dtable)) {
        rv = xqc_http3_ringbuf_reserve(&ctx->dtable,xqc_http3_ringbuf_len(&ctx->dtable) * 2);

        if(rv != 0){

            return -1;
        }
    }
#endif

    ctx->dtable_size += space;
    ctx->dtable_sum += space;

    return 0;
}



int xqc_http3_qpack_decoder_dtable_duplicate_add(xqc_http3_qpack_decoder * decoder){

    int rv;
    xqc_http3_qpack_entry * entry;

    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, decoder->rstate.absidx);

    //char *buf = malloc(xqc_max(entry->nv.name_len, entry->nv.value_len));

    char *name_buf = malloc(entry->nv.name_len);

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, entry->nv.name_len);

    char *value_buf = malloc(entry->nv.value_len);
    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, value_buf, entry->nv.value_len);


    rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, entry->nv.name_len, value_buf,  entry->nv.value_len, NULL);

    if(name_buf)free(name_buf);
    if(value_buf)free(value_buf);
    if(rv < 0){
        return rv;
    }

    return 0;
}

int xqc_http3_qpack_decoder_dtable_dynamic_add(xqc_http3_qpack_decoder * decoder){

    xqc_http3_qpack_entry *entry;
    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, decoder->rstate.absidx);

    char *name_buf = malloc(entry->nv.name_len);

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, entry->nv.name_len);


    char *value_buf = decoder->rstate.value->data;
    size_t value_len = decoder->rstate.value->used_len;


    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, entry->nv.name_len, value_buf, value_len, NULL);

    return rv;

}


int xqc_http3_qpack_decoder_dtable_static_add(xqc_http3_qpack_decoder * decoder){
    size_t absidx = decoder->rstate.absidx;
    xqc_qpack_static_table_entry * s_entry = xqc_get_qpack_static_table_entry(absidx);

    char * name = s_entry->name;
    size_t name_len = s_entry->name_len;

    char *value_buf = decoder->rstate.value->data;
    size_t value_len = decoder->rstate.value->used_len;


    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name, name_len, value_buf, value_len, NULL);

    return rv;
}



int xqc_http3_qpack_decoder_dtable_indexed_add(xqc_http3_qpack_decoder * decoder){

    if(decoder->rstate.dynamic){
        return xqc_http3_qpack_decoder_dtable_dynamic_add(decoder);
    }

    return xqc_http3_qpack_decoder_dtable_static_add(decoder);

}

int xqc_http3_qpack_decoder_dtable_literal_add(xqc_http3_qpack_decoder * decoder){


    char * name_buf = decoder->rstate.name->data;
    size_t name_len = decoder->rstate.name->used_len;

    char * value_buf = decoder->rstate.value->data;
    size_t value_len = decoder->rstate.value->used_len;

    if(xqc_table_space(name_len, value_len) > decoder->ctx.max_dtable_size) {
        return -1;
    }

    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, name_len, value_buf, value_len, NULL);
    return rv;
}



ssize_t xqc_http3_qpack_decoder_read_encoder(xqc_h3_conn_t *h3_conn, uint8_t * src, size_t srclen){

    uint8_t * p = src, * end = src + srclen;
    int rv = 0;
    ssize_t nread;
    int read_fin;

    xqc_http3_qpack_decoder_t * decoder = &h3_conn->qdec;
    for(; p!= end;){

        switch(decoder->state){

            case XQC_HTTP3_QPACK_ES_STATE_OPCODE:
                if((*p) & 0x80){

                    decoder->opcode = XQC_HTTP3_QPACK_ES_OPCODE_INSERT_INDEXED;
                    decoder->rstate.dynamic = !((*p) & 0x40);
                    decoder->rstate.prefix = 6;
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_INDEX;
                }else if((*p) & 0x40){
                    decoder->opcode = XQC_HTTP3_QPACK_ES_OPCODE_INSERT;
                    decoder->rstate.dynamic = 0;
                    decoder->rstate.prefix = 5;
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_CHECK_NAME_HUFFMAN;
                }else if((*p) & 0x20){
                    decoder->opcode = XQC_HTTP3_QPACK_ES_OPCODE_SET_DTABLE_CAP;
                    decoder->rstate.prefix = 5;
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_INDEX;
                }else{
                    decoder->opcode = XQC_HTTP3_QPACK_ES_OPCODE_DUPLICATE;
                    decoder->rstate.dynamic = 1;
                    decoder->rstate.prefix = 5;
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_INDEX;
                }
                break;
            case XQC_HTTP3_QPACK_ES_STATE_READ_INDEX:
                nread = xqc_qpack_read_varint(&read_fin, &decoder->rstate, p, end);
                if(nread < 0){
                    rv = -1;
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return p - src;
                }
                if(decoder->opcode == XQC_HTTP3_QPACK_ES_OPCODE_SET_DTABLE_CAP){
                    xqc_http3_qpack_decoder_set_dtable_cap(decoder, decoder->rstate.left); //need check little than SETTINGS_QPACK_MAX_TABLE_CAPACITY
                    break;
                }

                rv = xqc_http3_qpack_decoder_rel2abs(decoder, &decoder->rstate);//
                if(rv < 0){
                    goto fail;
                }
                if(decoder->opcode == XQC_HTTP3_QPACK_ES_OPCODE_DUPLICATE) {
                    rv = xqc_http3_qpack_decoder_dtable_duplicate_add(decoder);//

                    if(rv != 0){
                        goto fail;
                    }

                    xqc_qpack_decoder_block_stream_check_and_process(h3_conn, decoder->ctx.next_absidx);
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                    xqc_http3_qpack_read_state_clear(&decoder->rstate);//need finish
                    break;
                }

                if(decoder->opcode == XQC_HTTP3_QPACK_ES_OPCODE_INSERT_INDEXED) {
                    decoder->rstate.prefix = 7;
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_CHECK_VALUE_HUFFMAN;
                    break;
                }

                goto fail;//cannot to here
            case XQC_HTTP3_QPACK_ES_STATE_CHECK_NAME_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&decoder->rstate, *p);
                decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_NAMELEN;
                decoder->rstate.left = 0;
                decoder->rstate.shift = 0;
            case XQC_HTTP3_QPACK_ES_STATE_READ_NAMELEN:
                nread = xqc_qpack_read_varint(&read_fin, &decoder->rstate, p, end);
                if(nread < 0){
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return (p - src);
                }

                if(decoder->rstate.huffman_encoded){
                    //haffman just later support
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_NAME_HUFFMAN;
                    //need finish;
                }else{

                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_NAME;
                    //if(decoder->rstate.name == NULL){
                    //}
                    decoder->rstate.name = xqc_var_buf_create(decoder->rstate.left + 1);
                }
                break;

            case XQC_HTTP3_QPACK_ES_STATE_READ_NAME_HUFFMAN:
                //need finish
                break;

            case XQC_HTTP3_QPACK_ES_STATE_READ_NAME:
                nread = xqc_qpack_read_string(&decoder->rstate, &decoder->rstate.name, p, end);

                if (nread < 0) {
                    rv = (int)nread;
                    goto fail;
                }

                p += nread;

                if (decoder->rstate.left) {
                    return p - src;
                }

                decoder->state = XQC_HTTP3_QPACK_ES_STATE_CHECK_VALUE_HUFFMAN;
                break;
            case XQC_HTTP3_QPACK_ES_STATE_CHECK_VALUE_HUFFMAN:
                xqc_qpack_read_state_check_huffman(&decoder->rstate, *p);
                decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_VALUELEN;
                decoder->rstate.left = 0;
                decoder->rstate.shift = 0;
            case XQC_HTTP3_QPACK_ES_STATE_READ_VALUELEN:
                nread = xqc_qpack_read_varint(&read_fin, &decoder->rstate, p, end);
                if(nread < 0){
                    goto fail;
                }
                p += nread;

                if(!read_fin){
                    return p - src;
                }

                if(decoder->rstate.huffman_encoded){
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_VALUE_HUFFMAN;
                    //need finish
                }else{
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_VALUE;
                    //if(decoder->rstate.name == NULL){
                    //}
                    decoder->rstate.value = xqc_var_buf_create(decoder->rstate.left + 1);
                }

                break;//need finish
            case XQC_HTTP3_QPACK_ES_STATE_READ_VALUE_HUFFMAN:
                //need finish
                goto fail;
            case XQC_HTTP3_QPACK_ES_STATE_READ_VALUE:
                //need finish
                nread = xqc_qpack_read_string(&decoder->rstate, &decoder->rstate.value, p, end);

                if(nread < 0){

                    rv = (int)nread;
                    goto fail;
                }

                p += nread;

                if(decoder->rstate.left){

                    return p - src;
                }

                switch(decoder->opcode){

                    case XQC_HTTP3_QPACK_ES_OPCODE_INSERT_INDEXED:
                        rv = xqc_http3_qpack_decoder_dtable_indexed_add(decoder);
                        break;
                    case XQC_HTTP3_QPACK_ES_OPCODE_INSERT:
                        rv = xqc_http3_qpack_decoder_dtable_literal_add(decoder);
                        break;
                    default:
                        goto fail;
                }
                if(rv != 0){

                    goto fail;
                }
                xqc_qpack_decoder_block_stream_check_and_process(h3_conn, decoder->ctx.next_absidx);

                decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&decoder->rstate);
                break;
        }
    }

    return (p - src);

fail:
    return -1;
}


int xqc_http3_qpack_encoder_add_insert_count(xqc_http3_qpack_encoder * encoder, size_t n){

    if(encoder->ctx.next_absidx < encoder->krcnt + n){
        //means decoder return error insert count
        return -1;
    }

    encoder->krcnt += n;
    //xqc_http3_qpack_encoder_unblock(encoder, encoder->krcnt);//sender do not block, so no block stream list

    return 0;
}

int xqc_http3_qpack_check_and_refresh_insert_count(xqc_http3_qpack_encoder * encoder, size_t max_rcnt){

    if(encoder->krcnt < max_rcnt){
        encoder->krcnt = max_rcnt;
    }

    return 0;
}

int xqc_http3_qpack_encoder_insert_unack_header(xqc_h3_stream_t * qenc_stream, xqc_h3_stream_t *h3_stream, xqc_http3_qpack_encoder * encoder,
        uint64_t min_rcnt, uint64_t max_rcnt){
    xqc_qpack_unack_header_block * unack_block = malloc(sizeof(xqc_qpack_unack_header_block));
    xqc_init_list_head(&unack_block->header_block_list);
    xqc_init_list_head(&unack_block->stream_in_list);
    unack_block->min_rcnt = min_rcnt;
    unack_block->max_rcnt = max_rcnt;
    unack_block->stream_id = h3_stream->stream->stream_id;

    xqc_list_head_t * p_hb_list = &encoder->unack_stream_head;

    xqc_list_head_t * pos;
    xqc_list_for_each(pos, p_hb_list){
        xqc_qpack_unack_header_block *p_ublock = xqc_list_entry(pos, xqc_qpack_unack_header_block, header_block_list);

        if(unack_block->min_rcnt  < p_ublock->min_rcnt){
            break;
        }
    }

    xqc_list_add_tail(&unack_block->header_block_list, pos);

    xqc_list_head_t * p_si_list = &h3_stream->unack_block_list;
    xqc_list_add_tail(&unack_block->stream_in_list, p_si_list);
    return 0;

}

int xqc_http3_qpack_encoder_ack_header(xqc_h3_conn_t * h3_conn, int64_t stream_id){

    xqc_connection_t * conn = h3_conn->conn;
    xqc_stream_t * stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    xqc_h3_stream_t * h3_stream = stream->user_data;


    xqc_list_head_t * head = &(h3_stream->unack_block_list);

    if(xqc_list_empty(head)){

        return -1;
    }

    xqc_list_head_t * block_head = head->next;

    xqc_qpack_unack_header_block * unack_block = xqc_list_entry(block_head, xqc_qpack_unack_header_block, stream_in_list);

    xqc_list_del(block_head);

    xqc_list_head_t * header_block = &unack_block->header_block_list;

    xqc_list_del(header_block);

    xqc_http3_qpack_check_and_refresh_insert_count(&h3_conn->qenc, unack_block->max_rcnt);

    return 0;
}

int xqc_qpack_free_unack_header_block(xqc_qpack_unack_header_block * header_block){

    if(header_block == NULL){
        return 0;
    }
    xqc_list_del(&header_block->header_block_list);

    xqc_list_del(&header_block->stream_in_list);

    free(header_block);
}

int xqc_http3_qpack_encoder_cancel_stream(xqc_h3_conn_t *h3_conn , int64_t stream_id){

    xqc_connection_t * conn = h3_conn->conn;
    xqc_stream_t * stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    xqc_h3_stream_t * h3_stream = stream->user_data;


    xqc_list_head_t * head = &(h3_stream->unack_block_list);

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        xqc_qpack_unack_header_block * header_block = xqc_list_entry(pos, xqc_qpack_unack_header_block, header_block_list);
        xqc_qpack_free_unack_header_block(header_block);
    }

#if 0

    head = &(h3_conn->block_stream_head);

    xqc_list_for_each_safe(pos, next, head){

        //need finish free block stream
        xqc_qpack_decoder_block_stream_t * blocked = xqc_list_entry(pos, xqc_qpack_decoder_block_stream_t, head_list);

        if(blocked->stream_id == stream_id){
            xqc_list_del(pos);
        }
    }
#endif

    //clear memory
    //questions?????????
    return 0;
}


ssize_t xqc_http3_qpack_encoder_read_decoder(xqc_h3_conn_t * h3_conn, uint8_t * src, size_t srclen){

    xqc_http3_qpack_encoder * encoder = &h3_conn->qenc;
    uint8_t * p = src, * end = src + srclen;
    int rv;
    ssize_t nread;
    int read_fin;
    for(; p!= end;){

        switch(encoder->state){
            case XQC_HTTP3_QPACK_DS_STATE_OPCODE:
                if((*p) & 0x80){

                    encoder->opcode = XQC_HTTP3_QPACK_DS_OPCODE_HEADER_ACK;
                    encoder->rstate.prefix = 7;
                }else if((*p) & 0x40){

                    encoder->opcode = XQC_HTTP3_QPACK_DS_OPCODE_STREAM_CANCEL;
                    encoder->rstate.prefix = 6;
                }else{

                    encoder->opcode = XQC_HTTP3_QPACK_DS_OPCODE_ICNT_INCREMENT;
                    encoder->rstate.prefix = 6;
                }
                encoder->state = XQC_HTTP3_QPACK_DS_STATE_READ_NUMBER;
            case XQC_HTTP3_QPACK_DS_STATE_READ_NUMBER:
                nread = xqc_qpack_read_varint(&read_fin, &encoder->rstate, p, end);
                if(nread < 0){
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return (p - src);
                }
                switch(encoder->opcode){

                    case XQC_HTTP3_QPACK_DS_OPCODE_ICNT_INCREMENT:
                        rv = xqc_http3_qpack_encoder_add_insert_count(encoder, encoder->rstate.left); //need finish
                        if(rv != 0){
                            goto fail;
                        }
                        break;
                    case XQC_HTTP3_QPACK_DS_OPCODE_HEADER_ACK:
                        xqc_http3_qpack_encoder_ack_header(h3_conn, (int64_t)encoder->rstate.left); //need finish
                        break;
                    case XQC_HTTP3_QPACK_DS_OPCODE_STREAM_CANCEL:
                        xqc_http3_qpack_encoder_cancel_stream(h3_conn, (int64_t)encoder->rstate.left); //need finish
                        break;
                    default:
                        return -1;
                }
                encoder->state = XQC_HTTP3_QPACK_DS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&encoder->rstate);
                break;
            default:
                return -1;
        }
    }

    return (p - src);

fail:
    return -1;
}

int xqc_qpack_context_check_draining(xqc_http3_qpack_context * ctx, xqc_http3_qpack_entry * entry){

    size_t safe_size = ctx->max_dtable_size - xqc_min(512, ctx->max_dtable_size * 1 / 8);
    int ret = (ctx->dtable_sum - entry->sum > safe_size) ? XQC_TRUE : XQC_FALSE;
}



int xqc_qpack_encoder_dtable_prepare_space(xqc_http3_qpack_encoder * encoder, size_t need){


    if(encoder->ctx.dtable_size + need < encoder->ctx.max_dtable_size){
        return 0;
    }
    uint64_t ref_idx = XQC_MAX_UINT64;
    if(xqc_list_empty(&encoder->unack_stream_head)){
        ref_idx = XQC_MAX_UINT64;
    }else{
        xqc_qpack_unack_header_block * u_hb = xqc_list_entry(encoder->unack_stream_head.next, xqc_qpack_unack_header_block, header_block_list);
        ref_idx = u_hb->min_rcnt;
    }

    xqc_http3_qpack_context *ctx = &encoder->ctx;
    while(encoder->ctx.dtable_size + need > encoder->ctx.max_dtable_size){
        if(xqc_http3_ringbuf_len(&ctx->dtable) == 0){ //empty
            break;
        }
        xqc_http3_qpack_entry * entry = (xqc_http3_qpack_entry *) xqc_http3_ringbuf_get(&ctx->dtable, xqc_http3_ringbuf_len(&ctx->dtable) -1);
        if(entry->absidx < ref_idx){ //little than means can be del
            xqc_http3_qpack_dtable_pop(ctx);
        }else{
            break;
        }

    }

    return 0;
}


int xqc_qpack_encoder_can_index(xqc_http3_qpack_encoder *encoder, size_t need){

    size_t avail = 0;
    if (encoder->ctx.max_dtable_size > encoder->ctx.dtable_size) {
        avail = encoder->ctx.max_dtable_size - encoder->ctx.dtable_size;
        if (need <= avail) {
            return XQC_TRUE;
        }
    }

    //need finish for max_dtable_size litter < dtable_size
    return XQC_FALSE;
}



int xqc_qpack_encoder_can_index_nv(xqc_http3_qpack_encoder *encoder, size_t name_len, size_t value_len){

    size_t need = xqc_table_space(name_len, value_len);
    xqc_qpack_encoder_dtable_prepare_space(encoder, need);
    return xqc_qpack_encoder_can_index(encoder, need);
}









int xqc_http3_qpack_encoder_write_static_indexed(xqc_http3_qpack_encoder * encoder,  xqc_var_buf_t **pp_buf, uint64_t absidx ){

    int ret = 0;
    ret = xqc_qpack_write_number( pp_buf, 0xc0, absidx, 6);
    return ret;
}



xqc_http3_qpack_indexing_mode xqc_qpack_encoder_decide_indexing_mode(xqc_http3_qpack_encoder * encoder, int * token, char * name, size_t name_len, char *value, size_t value_len, uint8_t flags) {

    if(flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX){
        return XQC_HTTP3_QPACK_INDEXING_MODE_NEVER;
    }


    *token = xqc_qpack_lookup_token(name, name_len);

    switch(*token){

        case XQC_HTTP3_QPACK_TOKEN_AUTHORIZATION:
            return XQC_HTTP3_QPACK_INDEXING_MODE_NEVER;
        case XQC_HTTP3_QPACK_TOKEN_COOKIE:
            if (value_len < 20) {
                return XQC_HTTP3_QPACK_INDEXING_MODE_NEVER;
            }
            break;
        case XQC_HTTP3_QPACK_TOKEN__PATH:
        case XQC_HTTP3_QPACK_TOKEN_AGE:
        case XQC_HTTP3_QPACK_TOKEN_CONTENT_LENGTH:
        case XQC_HTTP3_QPACK_TOKEN_ETAG:
        case XQC_HTTP3_QPACK_TOKEN_IF_MODIFIED_SINCE:
        case XQC_HTTP3_QPACK_TOKEN_IF_NONE_MATCH:
        case XQC_HTTP3_QPACK_TOKEN_LOCATION:
        case XQC_HTTP3_QPACK_TOKEN_SET_COOKIE:
            return XQC_HTTP3_QPACK_INDEXING_MODE_LITERAL;
    }

    if (xqc_table_space(name_len, value_len) >
            encoder->ctx.max_dtable_size * 3 / 4) {
        return XQC_HTTP3_QPACK_INDEXING_MODE_LITERAL;
    }

    return XQC_HTTP3_QPACK_INDEXING_MODE_STORE;
}

int xqc_http3_qpack_encoder_write_dynamic_indexed(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, xqc_http3_qpack_entry *entry, size_t base){

    size_t absidx = entry->absidx;
    if(absidx < base){
        return xqc_qpack_write_number( pp_buf, 0x80, base-absidx-1, 6);
    }
    return xqc_qpack_write_number(pp_buf, 0x10, absidx - base, 4);

}

int xqc_qpack_encoder_write_indexed_name(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t fb,
        size_t nameidx, size_t prefix, char * value, size_t value_len){

    //need finish huffman

    size_t len = xqc_http3_qpack_put_varint_len(nameidx, prefix);

    len += (xqc_http3_qpack_put_varint_len(value_len, 7) + value_len);

    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -1;
    }

    uint8_t * p = (*pp_buf)->data + (*pp_buf)->used_len;
    *p = fb;

    p = xqc_http3_qpack_put_varint(p, nameidx, prefix);


    p = xqc_http3_qpack_put_varint(p, value_len, 7);
    //memcpy(p, nv->value->data, nv->value->strlen);
    //p += nv->value->strlen;

    p = xqc_cpymem(p, value, value_len);
    (*pp_buf)->used_len += len;

    return 0;
}




int xqc_http3_qpack_encoder_write_static_insert(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, size_t nameidx, uint8_t * value, size_t value_len ){

    return xqc_qpack_encoder_write_indexed_name(encoder, p_enc_buf, 0xc0, nameidx, 6, value, value_len);

}

int xqc_http3_qpack_encoder_write_static_indexed_name(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf,
        uint64_t absidx, char * value, size_t value_len, uint8_t flags){

    //size_t absidx = entry->absidx;
    uint8_t fb = (uint8_t)(0x50 | ((flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX) ? 0x20 : 0));
    return xqc_qpack_encoder_write_indexed_name(encoder, pp_buf, fb, absidx, 4, value, value_len);
}


int xqc_qpack_encoder_write_duplicate_insert(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, xqc_http3_qpack_entry *entry){

    size_t idx = encoder->ctx.next_absidx - entry->absidx - 1;

    size_t len = xqc_http3_qpack_put_varint_len(idx, 5);
    uint8_t *p;
    int rv;

    *p_enc_buf = xqc_var_buf_save_prepare(*p_enc_buf, len);

    if(*p_enc_buf == NULL){

        return -1;
    }

    p = (*p_enc_buf)->data + (*p_enc_buf)->used_len;

    *p = 0;
    p = xqc_http3_qpack_put_varint(p, idx, 5);

    (*p_enc_buf)->used_len += len;
    return 0;
}


int xqc_http3_qpack_encoder_dtable_duplicate_add(xqc_http3_qpack_encoder * encoder, xqc_http3_qpack_entry *entry){

    char *name_buf = malloc(entry->nv.name_len);

    xqc_http3_ringdata_copy_data(&encoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, entry->nv.name_len);

    char *value_buf = malloc(entry->nv.value_len);
    xqc_http3_ringdata_copy_data(&encoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, value_buf, entry->nv.value_len);

    int rv = xqc_http3_qpack_context_dtable_add(&encoder->ctx, name_buf, entry->nv.name_len, value_buf, entry->nv.value_len, &encoder->dtable_hash);
    if(name_buf)free(name_buf);
    if(value_buf)free(value_buf);

    return rv;

}

int xqc_http3_qpack_encoder_write_dynamic_insert(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, size_t nameidx, uint8_t * value, size_t value_len){

    return xqc_qpack_encoder_write_indexed_name(encoder, p_enc_buf, 0x80,  encoder->ctx.next_absidx - nameidx - 1, 6, value, value_len);
}

int xqc_http3_qpack_encoder_write_dynamic_indexed_name(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf,
        uint64_t absidx, size_t base, char * value, size_t value_len, uint8_t flags){

    uint8_t fb;
    if(absidx < base){

        fb = (uint8_t)(0x40 | ((flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX) ? 0x20 : 0));
        return xqc_qpack_encoder_write_indexed_name(encoder, pp_buf, fb, base - absidx - 1, 4, value, value_len);
    }else{

        fb = (flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX) ? 0x08 : 0;
        return xqc_qpack_encoder_write_indexed_name(encoder, pp_buf, fb, absidx - base, 3, value, value_len);
    }
}

int xqc_http3_qpack_encoder_write_literal_insert(xqc_http3_qpack_encoder *encoder,  xqc_var_buf_t **p_enc_buf, char *name, size_t name_len, char * value, size_t value_len){

    return xqc_qpack_encoder_write_literal(encoder, p_enc_buf, 0x40, 5, name, name_len, value, value_len);

}

int xqc_http3_qpack_encoder_dtable_duplicate(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, xqc_http3_qpack_entry *entry){

    int can_insert = xqc_qpack_encoder_can_index_nv(encoder, entry->nv.name_len, entry->nv.value_len);

    if(can_insert){
        xqc_http3_qpack_encoder_dtable_duplicate_add(encoder, entry);
        xqc_qpack_encoder_write_duplicate_insert(encoder, p_enc_buf, entry);
    }

    return 0;
}

int xqc_http3_qpack_encoder_dtable_static_write(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, size_t nameidx, char * name, size_t name_len, char * value, size_t value_len){
    int can_insert = xqc_qpack_encoder_can_index_nv(encoder, name_len, value_len);

    if(can_insert){
        xqc_http3_qpack_encoder_write_static_insert(encoder, p_enc_buf, nameidx, value, value_len);
        xqc_http3_qpack_context_dtable_add(&(encoder->ctx), name, name_len, value, value_len, &encoder->dtable_hash);
    }

    return 0;
}

int xqc_http3_qpack_encoder_dtable_dynamic_write(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, size_t nameidx, char *name, size_t name_len, char * value, size_t value_len){

    int can_insert = xqc_qpack_encoder_can_index_nv(encoder, name_len, value_len);

    if(can_insert){
        xqc_http3_qpack_encoder_write_dynamic_insert(encoder, p_enc_buf, nameidx, value, value_len);
        xqc_http3_qpack_context_dtable_add(&(encoder->ctx), name, name_len, value, value_len, &encoder->dtable_hash);
    }
}

int xqc_http3_qpack_encoder_dtable_literal_write(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, char *name, size_t name_len, char * value, size_t value_len){

    int can_insert = xqc_qpack_encoder_can_index_nv(encoder, name_len, value_len);

    if(can_insert){
        xqc_http3_qpack_encoder_write_literal_insert(encoder, p_enc_buf, name, name_len, value, value_len);

        xqc_http3_qpack_context_dtable_add(&(encoder->ctx), name, name_len, value, value_len, &encoder->dtable_hash);
    }
}

int xqc_http3_qpack_encoder_encode_nv(xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder, size_t *pmax_cnt, size_t *pmin_cnt,
        xqc_var_buf_t **pp_buf, xqc_var_buf_t **p_enc_buf, xqc_http_header_t * header, size_t base){

    int baseIndex = 0;
    int largestRef = 0;

    int rv = 0;

    int token = 0;

    char * name = header->name.iov_base;
    size_t name_len = header->name.iov_len;
    char * value = header->value.iov_base;
    size_t value_len = header->value.iov_len;
    uint8_t flags = header->flags;
    uint8_t ack_flag = 0; // flag if can be referred
    xqc_http3_qpack_indexing_mode indexing_mode = xqc_qpack_encoder_decide_indexing_mode(encoder, &token, name, name_len, value, value_len, flags);

    xqc_http3_qpack_entry *entry = NULL;

    xqc_qpack_static_find_result s_result;
    xqc_qpack_find_result d_result;
    xqc_http3_qpack_stable_find(&s_result, token, name, name_len, value, value_len);
    if(indexing_mode != XQC_HTTP3_QPACK_INDEXING_MODE_NEVER){
        if(s_result.absidx != -1){//static name value
            rv = xqc_http3_qpack_encoder_write_static_indexed(encoder, pp_buf, s_result.absidx);
            return rv;
        }

    }

    xqc_http3_qpack_hash_find(&(encoder->dtable_hash), &(encoder->ctx.dtable_data), name, name_len, value, value_len, &d_result);

    if(indexing_mode != XQC_HTTP3_QPACK_INDEXING_MODE_NEVER){
        if(d_result.entry){//dynamic name value
            ack_flag = d_result.entry->absidx < encoder->krcnt;
            if(ack_flag){ //means can reference
                entry = d_result.entry;
                int draining = xqc_qpack_context_check_draining(&encoder->ctx, entry);
                if(draining){
                    xqc_http3_qpack_encoder_dtable_duplicate(encoder, p_enc_buf, entry);
                    goto literal;
                }else{
                    //refernce and no insert
                    rv = xqc_http3_qpack_encoder_write_dynamic_indexed(encoder, pp_buf, entry, base);
                    return rv;
                }
            }
        }
    }

    int insert_flag = (d_result.entry == NULL) && indexing_mode == XQC_HTTP3_QPACK_INDEXING_MODE_STORE ;
    if(s_result.name_absidx != -1){ //static name
        if(insert_flag){
            xqc_http3_qpack_encoder_dtable_static_write(encoder, p_enc_buf, s_result.name_absidx, name, name_len, value, value_len);
        }
        rv = xqc_http3_qpack_encoder_write_static_indexed_name(encoder, pp_buf, s_result.name_absidx, value, value_len, flags);
        return rv;
    }


    if(d_result.name_entry){ //dynamic name
        ack_flag = d_result.name_entry->absidx < encoder->krcnt;

        entry = d_result.name_entry;
        if(ack_flag){
            int draining = xqc_qpack_context_check_draining(&encoder->ctx, entry);
            if(draining){
                //do nothing
                goto literal;
            }else{
                if(insert_flag){
                    xqc_http3_qpack_encoder_dtable_dynamic_write(encoder, p_enc_buf, d_result.name_entry->absidx, name, name_len, value, value_len);
                }
                rv = xqc_http3_qpack_encoder_write_dynamic_indexed_name(encoder, pp_buf,  entry->absidx, base, value, value_len, flags );
                return rv;
            }
        }

    }

literal:
    if(insert_flag){ //将插入的过程变成一个接口，避免流程过于难懂
        xqc_http3_qpack_encoder_dtable_literal_write(encoder, p_enc_buf, name, name_len, value, value_len);
    }
    xqc_http3_qpack_encoder_write_literal(encoder, pp_buf, header->flags, name, name_len, value, value_len);

    return 0;
}


ssize_t xqc_http3_stream_write_header_block( xqc_h3_stream_t * qenc_stream, xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder,
     xqc_http_headers_t * headers, int fin){


    int rv = 0, i = 0;
    xqc_var_buf_t *pp_buf = NULL ;
    xqc_var_buf_t *pp_h_data = NULL;
    xqc_var_buf_t *p_enc_buf = NULL;

    pp_buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);
    p_enc_buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);

    size_t max_cnt = 0, min_cnt = XQC_MAX_SIZE_T;
    size_t base = 0;

    for(i = 0; i < headers->count; i++){
        rv = xqc_http3_qpack_encoder_encode_nv(stream, encoder, &max_cnt, &min_cnt, &pp_buf, &p_enc_buf, &headers->headers[i], base);
        if( rv != 0){
            goto fail;
        }
    }

    pp_h_data = xqc_var_buf_create((pp_buf)->used_len + XQC_VAR_INT_LEN * 2);

    int ret = xqc_http3_qpack_encoder_write_header_block_prefix( encoder, pp_h_data, max_cnt, base);

    if(ret < 0){
        goto fail;
    }

    pp_h_data = xqc_var_buf_save_data( pp_h_data, (pp_buf)->data, pp_buf->used_len);


    ssize_t send_size = xqc_http3_write_frame_header(stream, pp_h_data->data, pp_h_data->used_len, fin );

    if(send_size != pp_h_data->used_len){
        goto fail;
    }

    send_size = xqc_http3_qpack_encoder_stream_send(qenc_stream, p_enc_buf->data, p_enc_buf->used_len);

    if(send_size != p_enc_buf->used_len){
        goto fail;
    }

    xqc_http3_qpack_encoder_insert_unack_header(qenc_stream, stream, encoder, min_cnt, max_cnt);
    if(pp_buf){
        free(pp_buf);
    }

    if(pp_h_data){
        free(pp_h_data);
    }
    if(p_enc_buf){
        free(p_enc_buf);
    }
    return 0;
fail:
    if(pp_buf){
        free(pp_buf);
    }

    if(pp_h_data){
        free(pp_h_data);
    }
    if(p_enc_buf){
        free(p_enc_buf);
    }
    return -1;
}

int xqc_http_headers_create_buf(xqc_http_headers_t *headers, size_t capacity){

    headers->headers = malloc(sizeof(xqc_http_header_t) * capacity);
    memset(headers->headers, 0, sizeof(xqc_http_header_t) * capacity);
    headers->count = 0;
    headers->capacity = capacity;
    return 0;
}

int xqc_http_headers_realloc_buf(xqc_http_headers_t *headers, size_t capacity){

    if(headers->count > capacity){
        return -1;
    }
    xqc_http_header_t * old = headers->headers;

    headers->headers = malloc(sizeof(xqc_http_header_t) * capacity);

    if(headers->headers == NULL){
        free(old);
        headers->count = 0;
        headers->capacity = 0;
        return -1;
    }
    headers->capacity = capacity;

    memcpy(headers->headers, old, headers->count * sizeof(xqc_http_headers_t));

    free(old);
    return 0;
}



#define XQC_HEADERS_INIT_CAPACITY  32
int xqc_http3_http_headers_save_nv(xqc_http_headers_t * headers, xqc_qpack_name_value_t * nv){

    if(headers->capacity == 0){
        xqc_http_headers_create_buf(headers, XQC_HEADERS_INIT_CAPACITY);
    }
    if(headers->count >= headers->capacity){
        size_t capacity = xqc_min(headers->capacity * 2, headers->capacity + 128);
        if(xqc_http_headers_realloc_buf(headers, capacity) < 0){
            return -1;
        }
    }
    xqc_http_header_t * header  = &headers->headers[headers->count++];

    header->name.iov_base = malloc(nv->name->strlen + 1);
    header->name.iov_len = nv->name->strlen;
    header->value.iov_base = malloc(nv->value->strlen + 1);
    header->value.iov_len = nv->value->strlen;
    strncpy(header->name.iov_base, nv->name->data, header->name.iov_len + 1);
    strncpy(header->value.iov_base, nv->value->data, header->value.iov_len + 1);

    return 0;
}

int xqc_http3_handle_header_data(xqc_h3_conn_t * h3_conn, xqc_h3_stream_t * h3_stream){

    xqc_list_head_t * head = &h3_stream->recv_header_data_buf;
    xqc_list_head_t *pos, *next;
    xqc_data_buf_t * data_buf = NULL;
    int ret = 1;
    xqc_http3_qpack_decoder * decoder = &h3_conn->qdec;
    xqc_http3_qpack_stream_context *sctx = &h3_stream->qpack_sctx;

    xqc_qpack_name_value_t nv={NULL,NULL,0};

    xqc_h3_request_t * h3_request = h3_stream ->h3_request ;
    xqc_http_headers_t * headers = &h3_request->headers;

    xqc_list_for_each_safe(pos, next, head){
        data_buf = xqc_list_entry(pos, xqc_data_buf_t, list_head);


        char * start = data_buf->data + data_buf->already_consume;
        char * end = data_buf->data + data_buf->data_len;
        while(start < end){

            uint8_t flags = 0;
            int nread = xqc_http3_qpack_decoder_read_request_header(decoder, sctx, &nv, &flags,  start, end - start, data_buf->fin);

            if(nread <= 0){

                goto fail;
            }

            start += nread;
            if(flags & XQC_HTTP3_QPACK_DECODE_FLAG_EMIT){
                //save nv
                if(xqc_http3_http_headers_save_nv(headers, &nv) < 0){
                    xqc_qpack_name_value_free(&nv);
                    return -1;
                }
                xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|name:%s, value:%s|", nv.name->data, nv.value->data);
                xqc_qpack_name_value_free(&nv);
            }else if(flags & XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED){
                xqc_qpack_decoder_block_stream_insert(h3_stream, sctx->ricnt, &h3_conn->block_stream_head);
                h3_stream->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;
                data_buf->already_consume = start - data_buf->data;
                break;
            }else{
                if(start < end){
                    return -1;
                }
            }

        }

        if(h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED){

            break;
        }

        if(start == end){
            if( (data_buf->fin) ){
                h3_request->flag |= XQC_H3_REQUEST_HEADER_FIN;
            }
            xqc_list_del(pos);
            free(data_buf);
        }
    }

    if(xqc_list_empty(head)){
        h3_request->flag |= XQC_H3_REQUEST_HEADER_COMPLETE_RECV;
    }
    return 0;

fail:
    return -1;
}

