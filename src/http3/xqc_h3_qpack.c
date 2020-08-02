#include <xquic/xqc_errno.h>
#include "src/http3/xqc_h3_qpack.h"
#include "src/http3/xqc_h3_frame.h"
#include "src/http3/xqc_h3_qpack_token.h"
#include "src/transport/xqc_conn.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_hash.h"
#include "src/http3/xqc_h3_frame.h"
#include "src/http3/xqc_h3_request.h"


static size_t xqc_table_space(size_t namelen, size_t valuelen) {
    return XQC_HTTP3_QPACK_ENTRY_OVERHEAD + namelen + valuelen;
}


xqc_var_string_t * xqc_create_var_string(uint8_t * value, size_t strlen){

    xqc_var_string_t *v_str = xqc_malloc(sizeof(xqc_var_string_t) + strlen + 1);
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

void xqc_qpack_name_value_free(xqc_qpack_name_value_t *nv){

    if(nv == NULL){
        return;
    }
    if(nv->name){
        xqc_free(nv->name);
    }
    if(nv->value){
        xqc_free(nv->value);
    }
}

xqc_var_buf_t * xqc_var_buf_create(size_t capacity){

    xqc_var_buf_t * p = xqc_malloc(sizeof(xqc_var_buf_t) + capacity);
    if(p == NULL){
        return NULL;
    }
    p->capacity = capacity;
    p->used_len = 0;
    return p;
}

int xqc_var_buf_clear(xqc_var_buf_t *vbuf){
    vbuf->used_len = 0;
    return 0;
}

void xqc_var_buf_free(xqc_var_buf_t * vbuf){
    if(vbuf){
        xqc_free(vbuf);
    }
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
    xqc_free(src);
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

ssize_t xqc_qpack_read_huffman_string(xqc_http3_qpack_read_state *rstate,
        xqc_var_buf_t * dest, uint8_t *begin, uint8_t *end) {

    ssize_t nwrite;
    size_t len = (size_t)(end - begin);
    int fin = 0;

    if (len >= rstate->left) {
        len = rstate->left;
        end = begin + rstate->left;
        fin = 1;
    }

    nwrite = xqc_http3_qpack_huffman_decode(&rstate->huffman_ctx, dest->data + dest->used_len, begin, len, fin);

    if (nwrite < 0) {
        return nwrite;
    }

    dest->used_len += nwrite;
    rstate->left -= len;
    return (ssize_t)len;

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
            return -XQC_QPACK_DECODER_VARINT_ERROR;
        }
        if((XQC_HTTP3_QPACK_INT_MAX >> shift) < add){
            return -XQC_QPACK_DECODER_VARINT_ERROR;//bigger than max varint
        }
        add <<= shift;
        if(XQC_HTTP3_QPACK_INT_MAX - add < n){
            return -XQC_QPACK_DECODER_VARINT_ERROR; //too big
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


int xqc_http3_qpack_read_state_init(xqc_http3_qpack_read_state *rstate) {
    memset(rstate, 0, sizeof(xqc_http3_qpack_read_state));
    xqc_http3_qpack_huffman_decode_context_init(&rstate->huffman_ctx);
    rstate->name = xqc_var_buf_create(XQC_HTTP3_QPACK_MAX_NAME_BUFLEN); //预分配好,连接结束时释放
    if(rstate->name == NULL){
        return -XQC_H3_EMALLOC;
    }
    rstate->value = xqc_var_buf_create(XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN);

    if(rstate->value == NULL){
        xqc_var_buf_free(rstate->name);
        return -XQC_H3_EMALLOC;
    }

    return 0;
}

void xqc_http3_qpack_read_state_clear(xqc_http3_qpack_read_state *rstate) {
    xqc_var_buf_clear(rstate->name);
    xqc_var_buf_clear(rstate->value);
    rstate->left = 0;
    rstate->prefix = 0;
    rstate->shift = 0;
    rstate->absidx = 0;
    rstate->never = 0;
    rstate->dynamic = 0;
    rstate->huffman_encoded = 0;
    xqc_http3_qpack_huffman_decode_context_init(&rstate->huffman_ctx);
}

void xqc_http3_qpack_read_state_free(xqc_http3_qpack_read_state *rstate){
    if(rstate->name){
        xqc_var_buf_free(rstate->name);
        rstate->name = NULL;
    }
    if(rstate->value){
        xqc_var_buf_free(rstate->value);
        rstate->value = NULL;
    }
}

int xqc_qpack_encoder_write_literal_native(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t fb,
        size_t prefix, char * name, size_t name_len, char * value, size_t value_len){

    int rv;
    size_t len;
    len = 0;
    len += (xqc_http3_qpack_put_varint_len(name_len, prefix) + name_len);
    len += (xqc_http3_qpack_put_varint_len(value_len, 7) + value_len);

    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -XQC_H3_EMALLOC;
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

int xqc_qpack_encoder_write_literal(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t fb,
        size_t prefix, char * name, size_t name_len, char * value, size_t value_len){

    int rv;
    size_t len;
    size_t nhlen, vhlen;
    len = 0;

    int nh = 0, vh = 0;

    nhlen = xqc_http3_qpack_huffman_encode_count(name, name_len);
    if(nhlen < name_len){
        nh = 1;
        len += (xqc_http3_qpack_put_varint_len(nhlen, prefix) + nhlen);
    }else{
        len += (xqc_http3_qpack_put_varint_len(name_len, prefix) + name_len);
    }

    vhlen = xqc_http3_qpack_huffman_encode_count(value, value_len);
    if(vhlen < value_len){
        vh = 1;
        len += (xqc_http3_qpack_put_varint_len(vhlen, 7) + vhlen);
    }else{
        len += (xqc_http3_qpack_put_varint_len(value_len, 7) + value_len);
    }
    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -XQC_H3_EMALLOC;
    }

    uint8_t * p = (*pp_buf)->data + (*pp_buf)->used_len;

    *p = fb;
    if(nh){
        *p |= (uint8_t)(1 << prefix);
        p = xqc_http3_qpack_put_varint(p, nhlen, prefix);
        p = xqc_http3_qpack_huffman_encode(p, name, name_len);
    }else{
        p = xqc_http3_qpack_put_varint(p, name_len, prefix);
        p = xqc_cpymem(p, name, name_len);
    }
    *p = 0;
    if(vh){
        *p |= 0x80;
        p = xqc_http3_qpack_put_varint(p, vhlen, 7);
        p = xqc_http3_qpack_huffman_encode(p, value, value_len);
    } else {
        p = xqc_http3_qpack_put_varint(p, value_len, 7);
        p = xqc_cpymem(p, value, value_len);
    }
    //hex_print((*pp_buf)->data + (*pp_buf)->used_len, len + 1);
    (*pp_buf)->used_len += len;
    return 0;
}


int xqc_http3_qpack_encoder_write_literal(xqc_http3_qpack_encoder * encoder, xqc_var_buf_t **pp_buf, uint8_t flags, char *name, size_t name_len, char *value, size_t value_len){

    uint8_t fb = (uint8_t)(0x20 | ((flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX) ? 0x10 : 0));

    return xqc_qpack_encoder_write_literal(encoder, pp_buf, fb, 3, name, name_len, value, value_len);

}

int xqc_http3_qpack_encoder_write_header_block_prefix(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t *p_buf, size_t ricnt, size_t base){

    size_t max_ents = encoder->ctx.max_table_capacity/XQC_HTTP3_QPACK_ENTRY_OVERHEAD;

    size_t encricnt =  (ricnt == 0) ? 0 : ((ricnt %(2 * max_ents))+1); //absidx means ricnt in a [abs/(2*max_ents)*(2*max_ents, (1+abs/(2*max_ents))*2*max_ents], encrint only record offset

    int sign = base < ricnt;

    size_t delta_base = sign ? (ricnt - base - 1) : (base - ricnt);
    size_t len = xqc_http3_qpack_put_varint_len(encricnt, 8) + xqc_http3_qpack_put_varint_len(delta_base, 7);

    uint8_t *p;
    int rv = 0;

    if(len > p_buf->capacity - p_buf->used_len){

        return -XQC_QPACK_ENCODER_ERROR;//impossible
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
            return 1; //read only one byte
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
            return -XQC_QPACK_DECODER_VARINT_ERROR;//need return error
        }
        if((XQC_HTTP3_QPACK_INT_MAX >> shift) < add){
            return -XQC_QPACK_DECODER_VARINT_ERROR;//bigger than max varint
        }
        add <<= shift;
        if(XQC_HTTP3_QPACK_INT_MAX - add < n){
            return -XQC_QPACK_DECODER_VARINT_ERROR; //too big
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
        return -XQC_QPACK_DECODER_ERROR;
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
    return 0;
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
        return -XQC_H3_EMALLOC;
    }

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, nv->name->data, XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);

    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);

    if(nv->value == NULL){
        xqc_free(nv->name);
        return -XQC_H3_EMALLOC;
    }
    return 0;

}

int xqc_qpack_decoder_emit_static_indexed_name(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){
    nv->flag = sctx->rstate.never;

    int absidx = sctx->rstate.absidx;

    xqc_qpack_static_table_entry * entry = xqc_get_qpack_static_table_entry(absidx);
    if(entry == NULL){
        return -XQC_QPACK_DECODER_ERROR;
    }


    nv->name = xqc_create_var_string(entry->name, entry->name_len);
    if(nv->name == NULL){
        return -XQC_H3_EMALLOC;
    }
    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);

    if(nv->value == NULL){
        xqc_free(nv->name);
        return -XQC_H3_EMALLOC;
    }

    return 0;
}

int xqc_http3_qpack_decoder_emit_indexed_name(xqc_http3_qpack_decoder *decoder,
        xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv) {
    if(sctx->rstate.dynamic) {
        return xqc_qpack_decoder_emit_dynamic_indexed_name(decoder, sctx, nv);
    }else{
        return xqc_qpack_decoder_emit_static_indexed_name(decoder, sctx, nv);
    }

    return 0;
}


int xqc_http3_qpack_context_init(xqc_http3_qpack_context * ctx, uint64_t max_table_capacity, uint64_t max_dtable_size,
        uint64_t max_blocked){

    ctx->max_table_capacity = max_table_capacity;
    ctx->max_dtable_size = max_dtable_size;
    ctx->max_blocked = max_blocked;
    ctx->next_absidx = 0;
    ctx->dtable_size = 0;
    ctx->dtable_sum = 0;

    size_t nmemb = max_table_capacity/XQC_HTTP3_QPACK_ENTRY_OVERHEAD;
    int ret = 0;
    ret = xqc_http3_ringdata_init(&ctx->dtable_data, max_dtable_size);
    if(ret < 0){
        xqc_http3_ringdata_free(&ctx->dtable_data);
        return ret;
    }
    ret = xqc_http3_ringbuf_init(&ctx->dtable, nmemb, sizeof(xqc_http3_qpack_entry));
    if(ret < 0){
        xqc_http3_ringbuf_free(&ctx->dtable);
        return ret;
    }
    return 0;
}

void xqc_http3_qpack_context_free(xqc_http3_qpack_context * ctx){
    xqc_http3_ringdata_free(&ctx->dtable_data);
    xqc_http3_ringbuf_free(&ctx->dtable);
}



int 
xqc_h3_qpack_decoder_init(xqc_http3_qpack_decoder *qdec, 
    uint64_t max_table_capacity, uint64_t max_dtable_size, uint64_t max_blocked, xqc_h3_conn_t * h3_conn)
{
    qdec->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
    qdec->opcode = 0;
    xqc_http3_qpack_read_state_init(&qdec->rstate);

    xqc_http3_qpack_context_init(&qdec->ctx, max_table_capacity, max_dtable_size, max_blocked);

    qdec->written_icnt = 0;
    qdec->name_buf = xqc_malloc(XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);//1 byte for end char '\0'
    if(qdec->name_buf == NULL){
        return -XQC_H3_EMALLOC;
    }
    qdec->value_buf = xqc_malloc(XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN);//1 byte for end char '\0'
    if(qdec->value_buf == NULL){
        xqc_free(qdec->name_buf);
        qdec->value_buf = NULL;
        return -XQC_H3_EMALLOC;
    }

    qdec->h3_conn = h3_conn;

    return 0;
}

void xqc_http3_qpack_decoder_free(xqc_http3_qpack_decoder *qdec){

    xqc_http3_qpack_read_state_free(&qdec->rstate);
    xqc_http3_qpack_context_free(&qdec->ctx);
    if(qdec->name_buf){
        xqc_free(qdec->name_buf);
    }
    if(qdec->value_buf){
        xqc_free(qdec->value_buf);
    }
}

int xqc_qpack_hash_table_init(xqc_qpack_hash_table_t * htable, size_t element_count){

    htable->element_count = element_count;
    htable->list = xqc_malloc(element_count * sizeof(xqc_list_head_t));
    if(htable->list == NULL){
        return -XQC_H3_EMALLOC;
    }
    size_t i = 0;

    for(i = 0; i < element_count; i++){
        xqc_list_head_t * head = &htable->list[i];
        xqc_init_list_head(head);
    }

    return 0;
}

void xqc_qpack_hash_table_free(xqc_qpack_hash_table_t * htable){
    if(htable->list){
        xqc_free(htable->list);
    }
}

int 
xqc_h3_qpack_encoder_init(xqc_http3_qpack_encoder *qenc, 
    uint64_t max_table_capacity, uint64_t max_dtable_size,
    uint64_t max_blocked, size_t hash_table_size, xqc_h3_conn_t * h3_conn)
{

    memset(qenc, 0, sizeof(xqc_http3_qpack_encoder));
    xqc_http3_qpack_context_init(&qenc->ctx, max_table_capacity, max_dtable_size, max_blocked);

    qenc->state = XQC_HTTP3_QPACK_DS_STATE_OPCODE;
    qenc->opcode = 0;
    xqc_http3_qpack_read_state_init(&qenc->rstate);

    qenc->krcnt = 0;
    xqc_qpack_hash_table_init(&qenc->dtable_hash, hash_table_size);

    qenc->flags = 0;
    xqc_init_list_head(&qenc->unack_stream_head);

    qenc->name_buf = xqc_malloc(XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);
    if(qenc->name_buf == NULL){
        return -XQC_H3_EMALLOC;
    }
    qenc->value_buf = xqc_malloc(XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN);
    if(qenc->value_buf == NULL){
        xqc_free(qenc->name_buf);
        qenc->name_buf = NULL;
        return -XQC_H3_EMALLOC;
    }

    qenc->h3_conn = h3_conn;
    return 0;
}


int 
xqc_http3_qpack_encoder_free(xqc_http3_qpack_encoder *qenc)
{
    xqc_http3_qpack_context_free(&qenc->ctx);
    xqc_http3_qpack_read_state_free(&qenc->rstate);
    xqc_qpack_hash_table_free(&qenc->dtable_hash);

    if(qenc->name_buf){
        xqc_free(qenc->name_buf);
    }
    if(qenc->value_buf){
        xqc_free(qenc->value_buf);
    }

    xqc_list_head_t * p_hb_list = &qenc->unack_stream_head;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, p_hb_list){
        xqc_qpack_unack_header_block * u_hb = xqc_list_entry(pos, xqc_qpack_unack_header_block, header_block_list);

        xqc_list_del(&u_hb->stream_in_list);
        xqc_list_del(pos);
        xqc_free(u_hb);
    }

    return 0;
}

int xqc_http3_qpack_decoder_emit_literal(xqc_http3_qpack_decoder *decoder,
        xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv) {
    nv->name = xqc_create_var_string(sctx->rstate.name->data, sctx->rstate.name->used_len );
    if(nv->name == NULL){
        return -XQC_H3_EMALLOC;
    }
    nv->value = xqc_create_var_string(sctx->rstate.value->data, sctx->rstate.value->used_len);
    if(nv->value == NULL){
        xqc_free(nv->name);
        nv->name = NULL;
        return -XQC_H3_EMALLOC;
    }

    return 0;

}

int xqc_http3_qpack_decoder_pbrel2abs(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx){

    xqc_http3_qpack_read_state * rstate = &sctx->rstate;

    if(!rstate->dynamic){
        return -XQC_QPACK_DECODER_ERROR;
    }

    rstate->absidx = rstate->left + sctx->base;
    if(rstate->absidx >= sctx->ricnt) {
        return -XQC_QPACK_DECODER_ERROR;
    }

    return 0;
}
int xqc_http3_qpack_decoder_brel2abs(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx){

    xqc_http3_qpack_read_state * rstate = &sctx->rstate;
    if(rstate->dynamic) {
        if (sctx->base < rstate->left + 1) {
            return -XQC_QPACK_DECODER_ERROR;
        }
        rstate->absidx = sctx->base - rstate->left - 1;
        if (rstate->absidx >= sctx->ricnt) {
            return -XQC_QPACK_DECODER_ERROR;
        }
    }else{
        rstate->absidx = rstate->left;
    }
    return 0;

}

int xqc_qpack_decoder_emit_dynamic_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    nv->flag = sctx->rstate.never;

    uint64_t absidx = sctx->rstate.absidx;

    xqc_http3_qpack_entry * entry;

    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, absidx);


    nv->name = xqc_create_var_string(NULL, entry->nv.name_len);
    if(nv->name == NULL){
        return XQC_H3_EMALLOC;
    }

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, nv->name->data, nv->name->strlen+1);

    nv->value = xqc_create_var_string(NULL, entry->nv.value_len);
    if(nv->value == NULL){
        xqc_free(nv->name);
        return -XQC_H3_EMALLOC;
    }

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, nv->value->data, nv->value->strlen + 1);

    return 0;
}

int xqc_qpack_decoder_emit_static_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    nv->flag = sctx->rstate.never;

    int absidx = sctx->rstate.absidx;

    xqc_qpack_static_table_entry * entry = xqc_get_qpack_static_table_entry(absidx);
    if(entry == NULL){
        return -XQC_QPACK_DECODER_ERROR;
    }

    nv->name = xqc_create_var_string(entry->name, entry->name_len);
    if(nv->name == NULL){
        return -XQC_H3_EMALLOC;
    }
    nv->value = xqc_create_var_string(entry->value, entry->value_len);

    if(nv->value == NULL){
        xqc_free(nv->name);
        return -XQC_H3_EMALLOC;
    }
    return 0;

}

int xqc_http3_qpack_decoder_emit_indexed(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx, xqc_qpack_name_value_t *nv){

    if(sctx->rstate.dynamic) {
        return xqc_qpack_decoder_emit_dynamic_indexed(decoder, sctx, nv);
    }else{
        return xqc_qpack_decoder_emit_static_indexed(decoder, sctx, nv);
    }
    return 0;
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
        int ret = xqc_http3_handle_recv_data_buf(h3_conn, p_b_stream->h3_stream);
        xqc_free(p_b_stream);
        if(ret < 0){
            return ret;
        }
    }
    return 0;
}

int xqc_qpack_decoder_block_stream_insert(xqc_h3_stream_t * h3_stream, uint64_t ricnt, xqc_list_head_t *head){

    xqc_qpack_decoder_block_stream_t * block_stream = xqc_malloc(sizeof(xqc_qpack_decoder_block_stream_t)); //it will be free when free list
    if(block_stream == NULL){
        return -XQC_H3_EMALLOC;
    }

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
    int rv = -1;

    int rfin;
    ssize_t nread;

    *pflags = XQC_HTTP3_QPACK_DECODE_FLAG_NONE;

    for(; p < end; ){

        switch (sctx->state){

            case XQC_HTTP3_QPACK_RS_STATE_RICNT:
                nread = xqc_qpack_read_varint(&rfin, &sctx->rstate, p, end);
                if(nread < 0){
                    rv = -XQC_QPACK_DECODER_VARINT_ERROR;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_varint error, return value:%d|",nread);
                    goto fail;
                }
                p += nread;
                if(!rfin){
                    goto need_more_data;
                }

                rv = xqc_http3_qpack_decoder_reconstruct_ricnt(decoder, &sctx->ricnt, sctx->rstate.left);
                if(rv != 0){
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_reconstruct_ricnt error, return value:%d|",rv);
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
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_varint error, return value:%d|",nread);
                    rv = -XQC_QPACK_DECODER_VARINT_ERROR;
                    goto fail;
                }

                p += nread;
                if(!rfin){
                    goto need_more_data;
                }

                if(sctx->dbase_sign){//base 符号位
                    if(sctx->ricnt <  sctx->rstate.left){
                        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|dbase_sign mode error, sctx->dbase_sign:%d, sctx->ricnt:%d, sctx->rstate.left=%d|", sctx->dbase_sign, sctx->ricnt, sctx->rstate.left);
                        rv = -XQC_QPACK_DECODER_ERROR;
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
            case XQC_HTTP3_QPACK_RS_STATE_BLOCKED:
                if(sctx->ricnt > decoder->ctx.next_absidx) {
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|block stream read error, require count:%l, decoder absidx:%l|",sctx->ricnt, decoder->ctx.next_absidx);
                    return -XQC_QPACK_ENCODER_ERROR;
                }
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                sctx->rstate.left = 0;
                sctx->rstate.shift = 0;
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
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_varint error, return value:%d|",nread);
                    rv = -XQC_QPACK_DECODER_VARINT_ERROR;
                    goto fail;
                }

                p += nread;
                if(!rfin){
                    goto need_more_data;
                }

                switch(sctx->opcode) {
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED:
                        rv = xqc_http3_qpack_decoder_brel2abs(decoder, sctx);
                        if (rv != 0){
                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_brel2abs error, return value:%d|",rv);
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

                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_pbrel2abs error, return value:%d|",rv);
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
                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_brel2abs error, return value:%d|",rv);
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        rv = xqc_http3_qpack_decoder_pbrel2abs(decoder, sctx);
                        if (rv != 0) {
                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_pbrel2abs error, return value:%d|",rv);
                            goto fail;
                        }
                        sctx->rstate.prefix = 7;
                        sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                        break;
                    default:
                        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|unknown sctx->opcode:%d|",sctx->opcode);
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
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_varint error, return value:%d|",nread);
                    goto fail;
                }
                p += nread;
                if (!rfin) {
                    goto need_more_data;
                }
                if (sctx->rstate.left > XQC_HTTP3_QPACK_MAX_NAMELEN) {
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|name len exceed max_namelen, namelen:%d|", sctx->rstate.left);
                    goto fail;
                }
                if(sctx->rstate.huffman_encoded) {
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAME_HUFFMAN;
                    xqc_http3_qpack_huffman_decode_context_init(&sctx->rstate.huffman_ctx);
                    xqc_var_buf_clear(sctx->rstate.name);

                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_NAME;
                    xqc_var_buf_clear(sctx->rstate.name);
                }
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_NAME_HUFFMAN:
                nread = xqc_qpack_read_huffman_string(&sctx->rstate, sctx->rstate.name, p, end);
                if (nread < 0) {
                    rv = (int)nread;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_huffman_string error, return value:%d|",nread);
                    goto fail;
                }

                p += nread;

                if (sctx->rstate.left) {
                    goto need_more_data;
                }
                sctx->state = XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN;
                sctx->rstate.prefix = 7;
                break;

            case XQC_HTTP3_QPACK_RS_STATE_READ_NAME:
                nread = xqc_qpack_read_string(&sctx->rstate, &sctx->rstate.name, p, end);
                if (nread < 0) {
                    rv = (int)nread;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_string error, return value:%d|",nread);
                    goto fail;
                }

                p += nread;

                if (sctx->rstate.left) {
                    goto need_more_data;
                }

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
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_varint error, return value:%d|",nread);
                    rv = (int)nread;
                    goto fail;
                }

                p += nread;
                if(!rfin){
                    goto need_more_data;
                }

                if(decoder->rstate.left > XQC_HTTP3_QPACK_MAX_VALUELEN){
                    rv = -XQC_QPACK_DECODER_ERROR;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|value len exceed max_namelen, namelen:%d|", decoder->rstate.left);
                    goto fail;
                }

                if(sctx->rstate.huffman_encoded){
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUE_HUFFMAN;
                    xqc_http3_qpack_huffman_decode_context_init(&sctx->rstate.huffman_ctx);
                    xqc_var_buf_clear(sctx->rstate.value);
                }else{
                    sctx->state = XQC_HTTP3_QPACK_RS_STATE_READ_VALUE;
                    xqc_var_buf_clear(sctx->rstate.value);

                }
                break;
            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUE_HUFFMAN:

                nread = xqc_qpack_read_huffman_string(&sctx->rstate, sctx->rstate.value, p, end);
                if(nread < 0){
                    rv = (int)nread;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_string error, return value:%d|",nread);
                    goto fail;
                }

                p += nread;

                if(sctx->rstate.left){
                    goto need_more_data;
                }

                switch(sctx->opcode){
                    case XQC_HTTP3_QPACK_RS_OPCODE_LITERAL:
                        if(xqc_http3_qpack_decoder_emit_literal(decoder, sctx, nv) < 0){
                            rv = -XQC_QPACK_DECODER_ERROR;
                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_emit_literal error|");
                            goto fail;
                        }
                        break;

                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        xqc_http3_qpack_decoder_emit_indexed_name(decoder, sctx, nv);
                        break;
                    default:
                        /* Unreachable */
                        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|unknown opcode, opcode:%d|", sctx->opcode);
                        rv = -XQC_QPACK_DECODER_ERROR;
                        goto fail;
                }

                *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&sctx->rstate);

                return p - src;

            case XQC_HTTP3_QPACK_RS_STATE_READ_VALUE:
                nread = xqc_qpack_read_string(&sctx->rstate, &sctx->rstate.value, p, end);
                if(nread < 0){
                    rv = (int)nread;
                    xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_qpack_read_string error, return value:%d|",nread);
                    goto fail;
                }

                p += nread;

                if(sctx->rstate.left){
                    goto need_more_data;
                }

                switch(sctx->opcode){
                    case XQC_HTTP3_QPACK_RS_OPCODE_LITERAL:
                        if(xqc_http3_qpack_decoder_emit_literal(decoder, sctx, nv) < 0){
                            rv = -XQC_QPACK_DECODER_ERROR;
                            xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_qpack_decoder_emit_literal error|");
                            goto fail;
                        }
                        break;

                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME:
                    case XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB:
                        xqc_http3_qpack_decoder_emit_indexed_name(decoder, sctx, nv);
                        break;
                    default:
                        /* Unreachable */

                        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|unknown opcode, opcode:%d|", sctx->opcode);
                        rv = -XQC_QPACK_DECODER_ERROR;
                        goto fail;
                }

                *pflags |= XQC_HTTP3_QPACK_DECODE_FLAG_EMIT;

                sctx->state = XQC_HTTP3_QPACK_RS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&sctx->rstate);

                return p - src;
            default:
                xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|unknown decoder state , sctx->state:%d|", sctx->state);
                goto fail;
        }
    }

need_more_data:
    if(fin){
        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|need more data but frame or stream fin, sctx->state:%d|", sctx->state);
        return -XQC_QPACK_DECODER_ERROR;
    }
    return p - src;

fail:
    return rv;
}


int xqc_http3_qpack_stream_context_init(xqc_http3_qpack_stream_context *sctx, uint64_t stream_id){

    memset(sctx, 0, sizeof(xqc_http3_qpack_stream_context));

    xqc_http3_qpack_read_state_init(&sctx->rstate);
    xqc_init_list_head(&sctx->block_list);
    sctx->rstate.prefix = 8;
    sctx->state = XQC_HTTP3_QPACK_RS_STATE_RICNT;
    sctx->opcode = 0;
    sctx->stream_id = stream_id;
    sctx->ricnt = 0;
    sctx->dbase_sign = 0;
    sctx->base = 0;

    return 0;
}

int xqc_http3_qpack_stream_context_reinit(xqc_http3_qpack_stream_context *sctx){

    xqc_http3_qpack_read_state_clear(&sctx->rstate);
    sctx->rstate.prefix = 8;
    sctx->state = XQC_HTTP3_QPACK_RS_STATE_RICNT;
    sctx->opcode = 0;
    sctx->ricnt = 0;
    sctx->dbase_sign = 0;
    sctx->base = 0;

    return 0;

}

void xqc_http3_qpack_stream_context_free(xqc_http3_qpack_stream_context * sctx){

    if(sctx == NULL){
        return;
    }
    //free block_list
    xqc_http3_qpack_read_state_free(&sctx->rstate);
}

int xqc_http3_ringdata_pop_back(xqc_http3_ringdata *rdata, xqc_http3_qpack_entry *entry){

    int ret = 0;
    ret = xqc_http3_ringdata_out_queue(rdata, entry->nv.name_index, entry->nv.name_len);
    if(ret < 0){
        return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
    }

    ret = xqc_http3_ringdata_out_queue(rdata, entry->nv.value_index, entry->nv.value_len);
    if(ret < 0){
        return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
    }
    return 0;
}



int xqc_http3_qpack_dtable_pop(xqc_http3_qpack_context *ctx){

    int i = 0;
    i = xqc_http3_ringbuf_len(&ctx->dtable);
    xqc_http3_qpack_entry * entry = (xqc_http3_qpack_entry *) xqc_http3_ringbuf_get(&ctx->dtable, i-1);

    ctx->dtable_size -= xqc_table_space(entry->nv.name_len, entry->nv.value_len);
    if(xqc_http3_ringdata_pop_back(&ctx->dtable_data, entry) < 0){
        return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
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
        ref_idx = u_hb->min_rcnt - 1;
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


//int xqc_http3_qpack_encoder_expand_dtable_size(xqc_http3_qpack_encoder *encoder, size_t cap){
int xqc_http3_qpack_encoder_expand_dtable_size(xqc_http3_qpack_context *ctx, size_t cap){

    xqc_http3_ringdata *rdata = &(ctx->dtable_data);
    if(rdata->capacity > cap){
        return 0; //no need expand
    }

    size_t msize = 1;
    for(; msize < cap; msize = msize << 1);

    char * buf = xqc_malloc(msize);
    if(buf == NULL){
        return -XQC_H3_EMALLOC;
    }
    size_t capacity = msize;
    size_t mask = msize - 1;

    size_t i = xqc_http3_ringbuf_len(&ctx->dtable);
    if(i == 0){
        goto end;  //need copy
    }
    xqc_http3_qpack_entry *ent = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, 0);

    size_t abs_index = ent->nv.name_index;

    xqc_http3_ringdata_copy_data_to_buf(rdata, abs_index, rdata->used, buf, mask);

end:
    xqc_free(rdata->buf);
    rdata->buf = buf;
    rdata->capacity = capacity;
    rdata->mask = mask;
    return 0;
}

int xqc_qpack_write_number(xqc_var_buf_t **pp_buf, uint8_t fb, uint64_t num, size_t prefix){

    size_t len = xqc_http3_qpack_put_varint_len(num, prefix);

    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -XQC_H3_EMALLOC;
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
        return -XQC_QPACK_SET_DTABLE_CAP_ERROR;
    }

    if(ctx->dtable_size < cap){ //只支持设置大，如果设置小则不做动作
        ctx->max_dtable_size = cap;
        return xqc_qpack_write_number(p_enc_buf, 0x20, cap, 5);

    }else{



    }

    return 0;

}

int xqc_http3_qpack_decoder_set_dtable_cap(xqc_http3_qpack_decoder * decoder, size_t cap){ //缓存大小调整，在调整大的时候扩大缓存的实现暂未实现, 调整小时不缩小缓存的内存

    xqc_http3_qpack_entry *ent;
    size_t i;
    ssize_t ret;
    xqc_http3_qpack_context *ctx = &decoder->ctx;

    if(cap > ctx->max_table_capacity){
        return -XQC_QPACK_SET_DTABLE_CAP_ERROR;
    }

    ctx->max_dtable_size = cap;

    if(ctx->max_dtable_size > ctx->dtable_data.capacity){
        ret = xqc_http3_qpack_encoder_expand_dtable_size(ctx, ctx->max_dtable_size);
        if(ret < 0){
            return -XQC_QPACK_SET_DTABLE_CAP_ERROR;
        }
    }

    while(ctx->dtable_size > cap){

        i = xqc_http3_ringbuf_len(&ctx->dtable);
        ent = (xqc_http3_qpack_entry *)xqc_http3_ringbuf_get(&ctx->dtable, i - 1);

        ctx->dtable_size -= xqc_table_space(ent->nv.name_len, ent->nv.value_len);

        ret = xqc_http3_ringdata_out_queue(&ctx->dtable_data, ent->nv.name_index, ent->nv.name_len);
        if(ret < 0){
            return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
        }
        ret = xqc_http3_ringdata_out_queue(&ctx->dtable_data, ent->nv.value_index, ent->nv.value_len);
        if(ret < 0){
            return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
        }

        xqc_http3_ringbuf_pop_back(&ctx->dtable);

    }

    //xqc_log(decoder->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:set dtable capacity, capacity:%d|", cap);
    return 0;
}

int xqc_http3_qpack_decoder_rel2abs(xqc_http3_qpack_decoder * decoder, xqc_http3_qpack_read_state * rstate){
    if(rstate->dynamic){

        if (decoder->ctx.next_absidx < rstate->left + 1) {
            return -XQC_QPACK_DECODER_ERROR;
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

    xqc_list_head_t * pos, * next;
    xqc_http3_qpack_entry * entry;

    xqc_list_for_each_safe(pos, next, head){

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

        return -XQC_QPACK_STATIC_TABLE_ERROR;
    }
    s_result->name_absidx = xqc_get_qpack_token_index_value(token);
    if(s_result->name_absidx == -1){
        s_result->absidx = -1;
        return 0;
    }

    int idx = s_result->name_absidx;
    for(; idx < xqc_get_qpack_static_table_size(); idx++){
        xqc_qpack_static_table_entry * s_entry = xqc_get_qpack_static_table_entry(idx);
        if(s_entry->name_len != name_len  || (0 == xqc_memeq(s_entry->name, name, name_len))){

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
        return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
    }
    xqc_http3_qpack_entry_init(entry, name_index, name_len, value_index, value_len,  ctx->dtable_sum, ctx->next_absidx++);

    if(dtable_hash != NULL){
        xqc_http3_qpack_hash_insert(dtable_hash, name, name_len, &entry->head_list);
    }

    ctx->dtable_size += space;
    ctx->dtable_sum += space;

    return 0;
}



int xqc_http3_qpack_decoder_dtable_duplicate_add(xqc_http3_qpack_decoder * decoder){

    int rv;
    xqc_http3_qpack_entry * entry;

    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, decoder->rstate.absidx);

    //char *buf = malloc(xqc_max(entry->nv.name_len, entry->nv.value_len));

    char *name_buf = decoder->name_buf;

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);

    char *value_buf = decoder->value_buf;
    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, value_buf, XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN);

    rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, entry->nv.name_len, value_buf, entry->nv.value_len, NULL);

    if(rv < 0){
        return rv;
    }

    return 0;
}

int xqc_http3_qpack_decoder_dtable_dynamic_add(xqc_http3_qpack_decoder * decoder){

    xqc_http3_qpack_entry *entry;
    entry = xqc_http3_qpack_context_dtable_get(&decoder->ctx, decoder->rstate.absidx);

    char *name_buf = decoder->name_buf;

    xqc_http3_ringdata_copy_data(&decoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);


    char *value_buf = decoder->rstate.value->data;
    size_t value_len = decoder->rstate.value->used_len;

    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, entry->nv.name_len, value_buf, value_len, NULL);
    if(rv == 0){
        //xqc_log(decoder->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:dynamic name index insert, name:%s, value:%s, index:%d|", name_buf, value_buf, entry->absidx);
    }

    return rv;

}


int xqc_http3_qpack_decoder_dtable_static_add(xqc_http3_qpack_decoder * decoder){
    size_t absidx = decoder->rstate.absidx;
    xqc_qpack_static_table_entry * s_entry = xqc_get_qpack_static_table_entry(absidx);

    if(s_entry == NULL){
        xqc_log(decoder->h3_conn->log, XQC_LOG_ERROR, "|absidx is invalid for static table, absidx:%d|", absidx);
        return -1;
    }
    char * name = s_entry->name;
    size_t name_len = s_entry->name_len;

    char *value_buf = decoder->rstate.value->data;
    size_t value_len = decoder->rstate.value->used_len;


    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name, name_len, value_buf, value_len, NULL);

    if(rv == 0){
        //xqc_log(decoder->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:static name index insert, name:%s, value:%s, index:%d|", name, value_buf, absidx);
    }

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
        return -XQC_QPACK_DYNAMIC_TABLE_ERROR;
    }

    int rv = xqc_http3_qpack_context_dtable_add(&decoder->ctx, name_buf, name_len, value_buf, value_len, NULL);
    return rv;
}





ssize_t xqc_http3_qpack_decoder_read_encoder(xqc_h3_conn_t *h3_conn, uint8_t * src, size_t srclen, int *insert_count){

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
                    rv = -XQC_QPACK_DECODER_VARINT_ERROR;
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return p - src;
                }
                if(decoder->opcode == XQC_HTTP3_QPACK_ES_OPCODE_SET_DTABLE_CAP){
                    rv = xqc_http3_qpack_decoder_set_dtable_cap(decoder, decoder->rstate.left); //need check little than SETTINGS_QPACK_MAX_TABLE_CAPACITY
                    if(rv < 0){
                        goto fail;
                    }
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                    xqc_http3_qpack_read_state_clear(&decoder->rstate);
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

                    (*insert_count) += 1;
                    //xqc_qpack_decoder_block_stream_check_and_process(h3_conn, decoder->ctx.next_absidx);
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                    xqc_http3_qpack_read_state_clear(&decoder->rstate);
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
                    rv = -XQC_QPACK_DECODER_VARINT_ERROR;
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return (p - src);
                }

                if(decoder->rstate.huffman_encoded){
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_NAME_HUFFMAN;
                    xqc_http3_qpack_huffman_decode_context_init(&decoder->rstate.huffman_ctx);
                    xqc_var_buf_clear(decoder->rstate.name);
                }else{
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_NAME;
                    xqc_var_buf_clear(decoder->rstate.name);
                }

                break;

            case XQC_HTTP3_QPACK_ES_STATE_READ_NAME_HUFFMAN:
                nread = xqc_qpack_read_huffman_string(&decoder->rstate, decoder->rstate.name, p, end);
                if (nread < 0) {
                    rv = (int)nread;
                    goto fail;
                }

                p += nread;

                if (decoder->rstate.left) {
                    return p - src;
                }

                decoder->rstate.prefix = 7;
                decoder->state = XQC_HTTP3_QPACK_ES_STATE_CHECK_VALUE_HUFFMAN;
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

                decoder->rstate.prefix = 7;
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
                    xqc_http3_qpack_huffman_decode_context_init(&decoder->rstate.huffman_ctx);
                    xqc_var_buf_clear(decoder->rstate.value);
                }else{
                    decoder->state = XQC_HTTP3_QPACK_ES_STATE_READ_VALUE;
                    xqc_var_buf_clear(decoder->rstate.value);
                }

                break;
            case XQC_HTTP3_QPACK_ES_STATE_READ_VALUE_HUFFMAN:
                nread = xqc_qpack_read_huffman_string(&decoder->rstate, decoder->rstate.value, p, end);
                if (nread < 0) {
                    rv = (int)nread;
                    goto fail;
                }

                p += nread;

                if (decoder->rstate.left) {
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
                (*insert_count) += 1;
                //xqc_qpack_decoder_block_stream_check_and_process(h3_conn, decoder->ctx.next_absidx);

                decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&decoder->rstate);
                break;

            case XQC_HTTP3_QPACK_ES_STATE_READ_VALUE:
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
                        rv = -XQC_QPACK_DECODER_ERROR;
                        goto fail;
                }
                if(rv != 0){
                    goto fail;
                }
                (*insert_count) += 1;
                //xqc_qpack_decoder_block_stream_check_and_process(h3_conn, decoder->ctx.next_absidx);
                decoder->state = XQC_HTTP3_QPACK_ES_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&decoder->rstate);
                break;
        }
    }

    return (p - src);

fail:
    return -rv;
}


int xqc_http3_qpack_encoder_add_insert_count(xqc_http3_qpack_encoder * encoder, size_t n){

    if(encoder->ctx.next_absidx < encoder->krcnt + n){
        return -XQC_QPACK_ENCODER_ERROR;
    }

    encoder->krcnt += n;
    xqc_log(encoder->h3_conn->log, XQC_LOG_INFO, "|qpack test mode:krcnt, krcnt:%d|", encoder->krcnt);
    return 0;
}

int xqc_http3_qpack_check_and_refresh_insert_count(xqc_http3_qpack_encoder * encoder, size_t max_rcnt){

    if(encoder->krcnt < max_rcnt){
        encoder->krcnt = max_rcnt;
        xqc_log(encoder->h3_conn->log, XQC_LOG_INFO, "|qpack test mode:krcnt, krcnt:%d|", encoder->krcnt);
    }
    return 0;
}

int xqc_http3_qpack_encoder_insert_unack_header(xqc_h3_stream_t * qenc_stream, xqc_h3_stream_t *h3_stream, xqc_http3_qpack_encoder * encoder,
        uint64_t min_rcnt, uint64_t max_rcnt){
    xqc_qpack_unack_header_block * unack_block = xqc_malloc(sizeof(xqc_qpack_unack_header_block));
    xqc_init_list_head(&unack_block->header_block_list);
    xqc_init_list_head(&unack_block->stream_in_list);
    unack_block->min_rcnt = min_rcnt;
    unack_block->max_rcnt = max_rcnt;
    unack_block->stream_id = h3_stream->stream->stream_id;

    xqc_list_head_t * p_hb_list = &encoder->unack_stream_head;

    xqc_list_head_t * pos, * next;
    xqc_list_for_each_safe(pos, next, p_hb_list){
        xqc_qpack_unack_header_block *p_ublock = xqc_list_entry(pos, xqc_qpack_unack_header_block, header_block_list);

        if(unack_block->min_rcnt  < p_ublock->min_rcnt){
            break;
        }
    }

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_INFO, "|qpack test mode: unack header block, min_rcnt:%z, max_rcnt:%z, stream_id:%lu",unack_block->min_rcnt, unack_block->max_rcnt, unack_block->stream_id);
    xqc_list_add_tail(&unack_block->header_block_list, pos);

    xqc_list_head_t * p_si_list = &h3_stream->unack_block_list;

    xqc_list_add_tail(&unack_block->stream_in_list, p_si_list);
    return 0;

}

int xqc_http3_qpack_encoder_ack_header(xqc_h3_conn_t * h3_conn, uint64_t stream_id){

    xqc_connection_t * conn = h3_conn->conn;
    xqc_stream_t * stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    xqc_h3_stream_t * h3_stream = stream->user_data;


    xqc_list_head_t * head = &(h3_stream->unack_block_list);

    if(xqc_list_empty(head)){

        return -XQC_QPACK_ENCODER_ERROR;
    }

    xqc_list_head_t * block_head = head->next;

    xqc_qpack_unack_header_block * unack_block = xqc_list_entry(block_head, xqc_qpack_unack_header_block, stream_in_list);

    xqc_log(h3_stream->h3_conn->log, XQC_LOG_INFO, "|qpack test mode: unack header block del, min_rcnt:%z, max_rcnt:%z, stream_id:%lu",unack_block->min_rcnt, unack_block->max_rcnt, unack_block->stream_id);

    xqc_list_del(block_head);

    xqc_list_head_t * header_block = &unack_block->header_block_list;

    xqc_list_del(header_block);

    xqc_http3_qpack_check_and_refresh_insert_count(&h3_conn->qenc, unack_block->max_rcnt);

    return 0;
}

void xqc_qpack_free_unack_header_block(xqc_qpack_unack_header_block * header_block){

    if(header_block == NULL){
        return;
    }
    xqc_list_del(&header_block->header_block_list);

    xqc_list_del(&header_block->stream_in_list);

    xqc_free(header_block);
}

int xqc_http3_qpack_clear_block_stream_list(xqc_h3_conn_t *h3_conn, uint64_t stream_id){

    xqc_list_head_t * head = &(h3_conn->block_stream_head);

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        xqc_qpack_decoder_block_stream_t * blocked = xqc_list_entry(pos, xqc_qpack_decoder_block_stream_t, head_list);

        if(blocked->stream_id == stream_id){
            xqc_list_del(pos);
            blocked->h3_stream->flags &= (~XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED);
            xqc_free(blocked);
        }
    }
    return 0;
}


int xqc_http3_stream_clear_unack_and_block_stream_list(xqc_h3_stream_t * h3_stream){
    xqc_list_head_t * head = &(h3_stream->unack_block_list);

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        xqc_qpack_unack_header_block * header_block = xqc_list_entry(pos, xqc_qpack_unack_header_block, stream_in_list);
        xqc_qpack_free_unack_header_block(header_block);
    }

    xqc_h3_conn_t *h3_conn = h3_stream->h3_conn;

    uint64_t stream_id = h3_stream->stream->stream_id;

    xqc_http3_qpack_clear_block_stream_list(h3_conn, stream_id);

    return 0;

}

int xqc_http3_qpack_encoder_cancel_stream(xqc_h3_conn_t *h3_conn , uint64_t stream_id){

    xqc_connection_t * conn = h3_conn->conn;
    xqc_stream_t * stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    xqc_h3_stream_t * h3_stream = stream->user_data;

    xqc_http3_stream_clear_unack_and_block_stream_list(h3_stream);


    return 0;
}


ssize_t xqc_http3_qpack_encoder_read_decoder(xqc_h3_conn_t * h3_conn, uint8_t * src, size_t srclen){

    xqc_http3_qpack_encoder * encoder = &h3_conn->qenc;
    uint8_t * p = src, * end = src + srclen;
    int rv = 0;
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
                    rv = XQC_QPACK_DECODER_VARINT_ERROR;
                    goto fail;
                }
                p += nread;
                if(!read_fin){
                    return (p - src);
                }
                switch(encoder->opcode){

                    case XQC_HTTP3_QPACK_DS_OPCODE_ICNT_INCREMENT:
                        rv = xqc_http3_qpack_encoder_add_insert_count(encoder, encoder->rstate.left);
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
                        rv = -XQC_QPACK_ENCODER_ERROR;
                        goto fail;
                }
                encoder->state = XQC_HTTP3_QPACK_DS_STATE_OPCODE;
                xqc_http3_qpack_read_state_clear(&encoder->rstate);
                break;
            default:
                rv = -XQC_QPACK_ENCODER_ERROR;
                goto fail;
        }
    }

    return (p - src);

fail:
    return rv;
}

int xqc_qpack_context_check_draining(xqc_http3_qpack_context * ctx, xqc_http3_qpack_entry * entry){

    size_t safe_size = ctx->max_dtable_size - xqc_min(512, ctx->max_dtable_size * 1 / 8);
    int ret = (ctx->dtable_sum - entry->sum > safe_size) ? XQC_TRUE : XQC_FALSE;
    return ret;
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
        ref_idx = u_hb->min_rcnt - 1;
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

    *token = xqc_qpack_lookup_token(name, name_len);
    if(flags & XQC_HTTP3_NV_FLAG_NEVER_INDEX){
        return XQC_HTTP3_QPACK_INDEXING_MODE_NEVER;
    }

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

    size_t len = xqc_http3_qpack_put_varint_len(nameidx, prefix);

    int vh = 0;
    size_t vhlen = xqc_http3_qpack_huffman_encode_count(value, value_len);
    if(vhlen < value_len){
        vh = 1;
        len +=  (xqc_http3_qpack_put_varint_len(vhlen, 7) + vhlen);
    }else{
        len += (xqc_http3_qpack_put_varint_len(value_len, 7) + value_len);
    }
    *pp_buf = xqc_var_buf_save_prepare(*pp_buf, len);

    if(*pp_buf == NULL){
        return -XQC_H3_EMALLOC;
    }

    uint8_t * p = (*pp_buf)->data + (*pp_buf)->used_len;
    *p = fb;

    p = xqc_http3_qpack_put_varint(p, nameidx, prefix);


    *p = 0;
    if(vh){
        *p |= 0x80;
        p = xqc_http3_qpack_put_varint(p, vhlen, 7);
        p = xqc_http3_qpack_huffman_encode(p, value, value_len);
    }else{
        p = xqc_http3_qpack_put_varint(p, value_len, 7);
        p = xqc_cpymem(p, value, value_len);
    }
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

        return -XQC_H3_EMALLOC;
    }

    p = (*p_enc_buf)->data + (*p_enc_buf)->used_len;

    *p = 0;
    p = xqc_http3_qpack_put_varint(p, idx, 5);

    (*p_enc_buf)->used_len += len;
    return 0;
}


int xqc_http3_qpack_encoder_dtable_duplicate_add(xqc_http3_qpack_encoder * encoder, xqc_http3_qpack_entry *entry){

    char *name_buf = encoder->name_buf;

    xqc_http3_ringdata_copy_data(&encoder->ctx.dtable_data, entry->nv.name_index, entry->nv.name_len, name_buf, XQC_HTTP3_QPACK_MAX_NAME_BUFLEN);

    char *value_buf = encoder->value_buf;
    xqc_http3_ringdata_copy_data(&encoder->ctx.dtable_data, entry->nv.value_index, entry->nv.value_len, value_buf, XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN);

    int rv = xqc_http3_qpack_context_dtable_add(&encoder->ctx, name_buf, entry->nv.name_len, value_buf, entry->nv.value_len, &encoder->dtable_hash);

    //xqc_log(encoder->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode: duplicate insert, name:%s, value:%s, index:%d|", name_buf, value_buf, entry->absidx);

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
        xqc_qpack_encoder_write_duplicate_insert(encoder, p_enc_buf, entry); //通知对端更新需要放在插入之前，因为插入会改变absidx,而通知对端计算相对index是根据插入前的absidx计算
        xqc_http3_qpack_encoder_dtable_duplicate_add(encoder, entry);
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

    int ret = 0;
    if(can_insert){
        ret = xqc_http3_qpack_encoder_write_dynamic_insert(encoder, p_enc_buf, nameidx, value, value_len);
        if(ret < 0){
            return ret;
        }
        ret = xqc_http3_qpack_context_dtable_add(&(encoder->ctx), name, name_len, value, value_len, &encoder->dtable_hash);
        if(ret < 0){
            return ret;
        }
    }
    return 0;
}

int xqc_http3_qpack_encoder_dtable_literal_write(xqc_http3_qpack_encoder *encoder, xqc_var_buf_t ** p_enc_buf, char *name, size_t name_len, char * value, size_t value_len){

    int can_insert = xqc_qpack_encoder_can_index_nv(encoder, name_len, value_len);

    if(can_insert){
        xqc_http3_qpack_encoder_write_literal_insert(encoder, p_enc_buf, name, name_len, value, value_len);

        xqc_http3_qpack_context_dtable_add(&(encoder->ctx), name, name_len, value, value_len, &encoder->dtable_hash);
    }
    return 0;
}

int xqc_http3_qpack_encoder_encode_nv(xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder, size_t *pmax_index, size_t *pmin_index,
        xqc_var_buf_t **pp_buf, xqc_var_buf_t **p_enc_buf, xqc_http_header_t * header, size_t base){

    int baseIndex = 0;
    int largestRef = 0;

    int rv = 0;

    int token = 0;

    unsigned char name_tmp[XQC_HTTP3_QPACK_MAX_NAME_BUFLEN];

    if (header->name.iov_len > XQC_HTTP3_QPACK_MAX_NAME_BUFLEN) {
        return -XQC_ENOBUF;
    }

    unsigned char * name = name_tmp;
    size_t name_len = header->name.iov_len;
    xqc_str_tolower(name, header->name.iov_base, name_len);

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

            //xqc_log(stream->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:static name_value_index, name:%s, value:%s, index:%d|", name, value, s_result.absidx);
            rv = xqc_http3_qpack_encoder_write_static_indexed(encoder, pp_buf, s_result.absidx);
            return rv;
        }

    }

    xqc_http3_qpack_hash_find(&(encoder->dtable_hash), &(encoder->ctx.dtable_data), name, name_len, value, value_len, &d_result);

    int insert_flag = (d_result.entry == NULL) && indexing_mode == XQC_HTTP3_QPACK_INDEXING_MODE_STORE ;

    if(indexing_mode != XQC_HTTP3_QPACK_INDEXING_MODE_NEVER){
        if(d_result.entry){//dynamic name value
            ack_flag = d_result.entry->absidx < encoder->krcnt;
            if(ack_flag){ //means can reference
                entry = d_result.entry;
                int draining = xqc_qpack_context_check_draining(&encoder->ctx, entry);
                if(draining){
                    //xqc_log(stream->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:draining, name:%s, value:%s, index:%d|", name, value, entry->absidx);
                    xqc_http3_qpack_encoder_dtable_duplicate(encoder, p_enc_buf, entry);
                    goto literal;
                }else{
                    //refernce and don't insert, refresh max ref index and min ref index
                    *pmax_index = xqc_max( *pmax_index, (entry->absidx + 1));
                    *pmin_index = xqc_min( *pmin_index, (entry->absidx + 1));
                    rv = xqc_http3_qpack_encoder_write_dynamic_indexed(encoder, pp_buf, entry, base);
                    //xqc_log(stream->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:name_value_index, name:%s, value:%s, index:%d|", name, value, entry->absidx);
                    return rv;
                }
            }
        }
    }

    if(s_result.name_absidx != -1){ //static name
        if(insert_flag){
            xqc_http3_qpack_encoder_dtable_static_write(encoder, p_enc_buf, s_result.name_absidx, name, name_len, value, value_len);
        }
        //xqc_log(stream->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:static name_index, name:%s, value:%s, index:%d|", name, value, s_result.name_absidx);
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

                //refresh max ref index and min ref index
                *pmax_index = xqc_max( *pmax_index, (entry->absidx + 1));
                *pmin_index = xqc_min( *pmin_index, (entry->absidx + 1));

                //xqc_log(stream->h3_conn->log, XQC_LOG_INFO, "|qpack test case: mode:name_index, name:%s, value:%s, index:%d|", name, value, entry->absidx);
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


ssize_t 
xqc_h3_stream_write_header_block(xqc_h3_stream_t * qenc_stream, 
    xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder,
    xqc_http_headers_t * headers, int fin)
{
    int rv = 0, i = 0;
    xqc_var_buf_t *pp_buf = NULL ;
    xqc_var_buf_t *pp_h_data = NULL;
    xqc_var_buf_t *p_enc_buf = NULL;

    pp_buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);
    p_enc_buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);

    size_t max_cnt = 0, min_cnt = XQC_MAX_SIZE_T;
    size_t base = encoder->ctx.next_absidx;;

    for(i = 0; i < headers->count; i++){
        rv = xqc_http3_qpack_encoder_encode_nv(stream, encoder, &max_cnt, &min_cnt, &pp_buf, &p_enc_buf, &headers->headers[i], base);
        if( rv != 0){
            goto fail;
        }
    }
    if(pp_buf->used_len == 0){
        goto ok; //no need send data
    }

    pp_h_data = xqc_var_buf_create((pp_buf)->used_len + XQC_VAR_INT_LEN * 2);

    if(pp_h_data == NULL){
        rv = -XQC_H3_EMALLOC;
        goto fail;
    }
    rv = xqc_http3_qpack_encoder_write_header_block_prefix( encoder, pp_h_data, max_cnt, base);

    if(rv < 0){
        goto fail;
    }

    pp_h_data = xqc_var_buf_save_data( pp_h_data, (pp_buf)->data, pp_buf->used_len);


    ssize_t send_size = xqc_http3_write_frame_header(stream, pp_h_data->data, pp_h_data->used_len, fin );

    if(send_size != pp_h_data->used_len){
        rv = -XQC_QPACK_SEND_ERROR;
        goto fail;
    }

    rv = pp_h_data->used_len;

    if(p_enc_buf->used_len > 0){
        send_size = xqc_http3_qpack_encoder_stream_send(qenc_stream, p_enc_buf->data, p_enc_buf->used_len);
        if(send_size != p_enc_buf->used_len){
            rv = -XQC_QPACK_SEND_ERROR;
            goto fail;
        }
    }

    if(max_cnt != 0){
        xqc_http3_qpack_encoder_insert_unack_header(qenc_stream, stream, encoder, min_cnt, max_cnt);
    }
ok:
    if(pp_buf){
        xqc_free(pp_buf);
    }

    if(pp_h_data){
        xqc_free(pp_h_data);
    }
    if(p_enc_buf){
        xqc_free(p_enc_buf);
    }
    return rv;
fail:
    if(pp_buf){
        xqc_free(pp_buf);
    }

    if(pp_h_data){
        xqc_free(pp_h_data);
    }
    if(p_enc_buf){
        xqc_free(p_enc_buf);
    }
    return rv;
}

int xqc_http_headers_create_buf(xqc_http_headers_t *headers, size_t capacity){

    headers->headers = xqc_malloc(sizeof(xqc_http_header_t) * capacity);
    memset(headers->headers, 0, sizeof(xqc_http_header_t) * capacity);
    headers->count = 0;
    headers->capacity = capacity;
    return 0;
}

int xqc_http_headers_realloc_buf(xqc_http_headers_t *headers, size_t capacity){

    if(headers->count > capacity){
        return -XQC_QPACK_SAVE_HEADERS_ERROR;
    }
    xqc_http_header_t * old = headers->headers;

    headers->headers = xqc_malloc(sizeof(xqc_http_header_t) * capacity);

    if(headers->headers == NULL){
        xqc_free(old);
        headers->count = 0;
        headers->capacity = 0;
        return -XQC_QPACK_SAVE_HEADERS_ERROR;
    }
    headers->capacity = capacity;

    memcpy(headers->headers, old, headers->count * sizeof(xqc_http_header_t));

    xqc_free(old);
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
            return -XQC_QPACK_SAVE_HEADERS_ERROR;
        }
    }
    xqc_http_header_t * header  = &headers->headers[headers->count++];

    header->name.iov_base = xqc_malloc(nv->name->strlen + 1);
    header->name.iov_len = nv->name->strlen;
    header->value.iov_base = xqc_malloc(nv->value->strlen + 1);
    header->value.iov_len = nv->value->strlen;
    strncpy(header->name.iov_base, nv->name->data, header->name.iov_len + 1);
    strncpy(header->value.iov_base, nv->value->data, header->value.iov_len + 1);

    return 0;
}


int xqc_http3_qpack_decoder_write_header_ack(xqc_h3_stream_t * qdec_stream, uint64_t stream_id){

    size_t len = xqc_http3_qpack_put_varint_len(stream_id, 7);

    char buf[XQC_VAR_BUF_INIT_SIZE] = {0};

    buf[0] = 0x80;

    xqc_http3_qpack_put_varint(buf, stream_id, 7);

    ssize_t ret = xqc_http3_qpack_encoder_stream_send(qdec_stream, buf, len);

    if(ret != len){
        //need log
    }
    return 0;
}

int xqc_http3_qpack_decoder_write_insert_count_increment(xqc_h3_stream_t * qdec_stream, size_t insert_count){

    size_t len = xqc_http3_qpack_put_varint_len(insert_count, 6);

    char buf[XQC_VAR_BUF_INIT_SIZE] = {0};

    buf[0] = 0x0;

    xqc_http3_qpack_put_varint(buf, insert_count, 6);

    ssize_t ret = xqc_http3_qpack_encoder_stream_send(qdec_stream, buf, len);

    if(ret != len){
        //need log
    }
    return 0;

}

int
xqc_h3_check_malformed_headers(xqc_h3_stream_t * h3_stream)
{
    uint8_t cursor = h3_stream->h3_request->h3_header.writing_cursor;
    xqc_http_headers_t *headers = &h3_stream->h3_request->h3_header.headers[cursor];

    /* Malformed Requests and Responses: pseudo-header fields after regular-header fields. */
    int regular_header_fields_exist_flag = 0;
    for (int i = 0; i < headers->count; i++) {
        char* name = (char*)headers->headers[i].name.iov_base;
        if (name[0] == ':') {
            if (regular_header_fields_exist_flag) {
                return XQC_ERROR;
            }
        } else {
           regular_header_fields_exist_flag = 1;
        }
    }

    return XQC_OK;
}

int xqc_http3_handle_header_data_streaming(xqc_h3_conn_t *h3_conn,  xqc_h3_stream_t * h3_stream, char * data, size_t len, uint8_t fin_flag){


    int nread = 0;
    xqc_http3_qpack_decoder * decoder = &h3_conn->qdec;
    xqc_http3_qpack_stream_context *sctx = &h3_stream->qpack_sctx;

    xqc_qpack_name_value_t nv={NULL,NULL,0};

    xqc_h3_request_t * h3_request = h3_stream ->h3_request ;
    xqc_http_headers_t * headers = &h3_request->h3_header.headers[h3_request->h3_header.writing_cursor];

    char * start = data;
    char * end = data + len;
    while(start < end){
        uint8_t flags = 0;
        int read_len = xqc_http3_qpack_decoder_read_request_header(decoder, sctx, &nv, &flags,  start, end - start, fin_flag);

        if(read_len < 0){
            return read_len;
        }
        if(read_len == 0){ //impossible, 避免死循环
            break;
        }
        start += read_len;

        if(flags & XQC_HTTP3_QPACK_DECODE_FLAG_EMIT){
            //save nv
            if(xqc_http3_http_headers_save_nv(headers, &nv) < 0){
                xqc_qpack_name_value_free(&nv);
                return -XQC_QPACK_SAVE_HEADERS_ERROR;
            }
            xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|name:%s, value:%s|", nv.name->data, nv.value->data);
            xqc_qpack_name_value_free(&nv);
        }else if(flags & XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED){
            xqc_qpack_decoder_block_stream_insert(h3_stream, sctx->ricnt, &h3_conn->block_stream_head);
            h3_stream->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;
            break;
        }else{
            if(start < end){
                return -XQC_QPACK_DECODER_ERROR;
            }
        }

    }

    if(start == end){
        if(fin_flag & XQC_HTTP3_STREAM_FIN){
            h3_request->flag |= XQC_H3_REQUEST_HEADER_FIN;
        }

        if(fin_flag & XQC_HTTP3_FRAME_FIN){

            xqc_http3_qpack_stream_context_reinit(sctx);
            if(sctx->ricnt > 0){
                xqc_http3_qpack_decoder_write_header_ack(h3_conn->qdec_stream, h3_stream->stream->stream_id);
                if(sctx->ricnt > decoder->written_icnt){
                    decoder->written_icnt = sctx->ricnt;
                }
            }
            //h3_request->flag |= XQC_H3_REQUEST_HEADER_CAN_READ;

            if (XQC_OK != xqc_h3_check_malformed_headers(h3_stream)) {
                xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_check_malformed_headers error|");
                return -XQC_H3_INVALID_HEADER;
            }

            int ret = xqc_h3_request_header_notify_read(&h3_request->h3_header);
            if(ret < 0){
                return ret;
            }
        }

    }
    nread = (start - data);
    return nread;
}

