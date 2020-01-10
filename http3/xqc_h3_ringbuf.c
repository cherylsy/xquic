#include <string.h>

#include "common/xqc_config.h"
#include "xqc_h3_ringbuf.h"
#include "include/xqc_errno.h"
#include "common/xqc_malloc.h"

size_t xqc_pow2_upper(uint64_t size){
    size_t msize = 1;
    for(; msize < size; msize = msize << 1);
    return msize;
}
//nmemb must be power of 2
int xqc_http3_ringbuf_init(xqc_http3_ringbuf * rb, size_t nmemb, size_t size){

    //uint64_t msize = xqc_pow2_upper(size);
    uint64_t msize = size;
    uint64_t mmemb = xqc_pow2_upper(nmemb);
    rb->buf = xqc_malloc(mmemb * msize);
    if(rb->buf == NULL){
        return -XQC_H3_EMALLOC;;
    }

    rb->nmemb = mmemb;
    rb->size = msize;
    rb->first = 0;
    rb->len = 0;

    return 0;
}


void xqc_http3_ringbuf_free(xqc_http3_ringbuf *rb){

    if(rb == NULL || rb->buf == NULL){
        return;
    }

    xqc_free(rb->buf);
}

void * xqc_http3_ringbuf_push_front(xqc_http3_ringbuf * rb){

    if(rb->len == rb->nmemb){ //ringbuf full

        return NULL;
    }
    if(rb->first != 0){
        rb->first = (rb->first - 1 ) & (rb->nmemb - 1);
    }else{
        rb->first = rb->nmemb - 1;
    }

    rb->len = xqc_min(rb->nmemb, rb->len + 1);

    return (void *)&(rb->buf[rb->first * rb->size]);
}

void * xqc_http3_ringbuf_push_back(xqc_http3_ringbuf * rb){

    if(rb->len == rb->nmemb){
        return NULL;
    }
    size_t offset = (rb->first + rb->len) & (rb->nmemb - 1);
    ++rb->len;
    return (void *)&(rb->buf[offset * rb->size]);
}


void xqc_http3_ringbuf_pop_front(xqc_http3_ringbuf *rb){

    rb->first = (rb->first + 1) & (rb->nmemb - 1);
    rb->len--;
}

void xqc_http3_ringbuf_pop_back(xqc_http3_ringbuf *rb){
    rb->len--;
}


int xqc_http3_ringbuf_resize(xqc_http3_ringbuf *rb, size_t len){

    if(len > rb->nmemb){
        return -1;
    }
    rb->len = len;
    return 0;
}


void * xqc_http3_ringbuf_get(xqc_http3_ringbuf *rb, size_t offset){

    offset = (rb->first + offset) & (rb->nmemb - 1);
    return (void *)&(rb->buf[offset * rb->size]);
}

size_t xqc_http3_ringbuf_len(xqc_http3_ringbuf *rb){
    return rb->len;
}

int xqc_http3_ringbuf_full(xqc_http3_ringbuf *rb){

    return rb->len == rb->nmemb;
}

int xqc_http3_ringbuf_reserve(xqc_http3_ringbuf *rb, size_t memb){
    uint64_t nmemb = xqc_pow2_upper(memb);
    if(rb->nmemb >= nmemb){
        return -1;
    }


    uint8_t * buf = xqc_malloc(nmemb * rb->size);
    if(buf == NULL){

        return -XQC_H3_EMALLOC;;
    }

    if(rb->first + rb->len > rb->nmemb){

        memcpy(buf, rb->buf + rb->first * rb->size, (rb->nmemb - rb->first)*rb->size);
        memcpy(buf + (rb->nmemb - rb->first) * rb->size, rb->buf, (rb->len - (rb->nmemb - rb->first)) * rb->size);
    }else{

        memcpy(buf, rb->buf + rb->first,  rb->len * rb->size);
    }

    xqc_free(rb->buf);
    rb->buf = buf;
    rb->first = 0;
    rb->nmemb = nmemb;

    return 0;
}



//memsize must be power of 2
int xqc_http3_ringdata_init(xqc_http3_ringdata *rdata, size_t memsize){

    uint64_t msize = 1;
    //for(; msize < memsize; msize = msize << 1);
    msize = xqc_pow2_upper(memsize);
    rdata->buf = (uint8_t *)xqc_malloc(msize);
    if(rdata->buf == NULL){
        return -XQC_H3_EMALLOC;;
    }
    rdata->capacity = msize;
    rdata->mask = msize - 1;
    rdata->used = 0;
    rdata->used_start = 0;
    rdata->free_start = 0;
    return 0;
}

void xqc_http3_ringdata_free(xqc_http3_ringdata *rdata){
    if(rdata->buf){
        xqc_free(rdata->buf);
    }
}

uint64_t xqc_get_http3_ringdata_free_start(xqc_http3_ringdata *rdata){

    return rdata->free_start;
}

int xqc_http3_ringdata_copy_data(xqc_http3_ringdata *rdata, size_t abs_index, size_t data_len, uint8_t * buf, size_t buf_len){

    if(data_len >= buf_len){ //buf_len should bigger than data_len for end char '\0'
        return -1;
    }
    size_t rel_index = abs_index & (rdata->mask);
    uint64_t end = rel_index + data_len;
    if(end <= rdata->capacity){
        memcpy( buf, rdata->buf + rel_index, data_len);
    }else{
        memcpy( buf, rdata->buf + rel_index, rdata->capacity - rel_index);
        memcpy( buf + rdata->capacity - rel_index, rdata->buf, end - rdata->capacity);
    }
    buf[data_len] = '\0'; //add end char '\0' for print
    return 0;
}

//在扩张ringdata时，将所有数据从原来的ringdata buf 拷贝到新的ringdata buf
int xqc_http3_ringdata_copy_data_to_buf(xqc_http3_ringdata *rdata, size_t abs_index, size_t data_len, uint8_t * buf, size_t mask){

    size_t rel_index = abs_index & (rdata->mask);
    uint64_t end = rel_index + data_len;

    if(end <= rdata->capacity){
        memcpy( buf + (abs_index & mask), rdata->buf + rel_index, data_len);
    }else{
        memcpy( buf + (abs_index & mask), rdata->buf + rel_index, rdata->capacity - rel_index);
        memcpy( buf, rdata->buf, end - rdata->capacity);
    }

    return 0;
}

size_t xqc_http3_ringdata_get_rel_index(xqc_http3_ringdata * rdata, size_t abs_index){

    return  abs_index & (rdata->mask);

}

int xqc_http3_ringdata_in_queue(xqc_http3_ringdata *rdata, size_t * abs_index, uint8_t * data, size_t data_len){

    size_t total_len = data_len + 1;
    size_t free_size = rdata->capacity - rdata->used ;
    if(total_len > free_size){
        return -1; // imposible except error
    }

    *abs_index = rdata->free_start;
    size_t end = ((rdata->free_start)&(rdata->mask)) + data_len;

    uint64_t index = (rdata->free_start)&(rdata->mask);
    if(end <= rdata->capacity){

        memcpy(rdata->buf + index, data, data_len);
    }else{

        memcpy(rdata->buf + index, data, rdata->capacity - index);
        memcpy(rdata->buf,  data + (rdata->capacity - index), (end - rdata->capacity));
    }
    rdata->buf[end & (rdata->mask)] = '\0';

    rdata->free_start += total_len;
    rdata->used += total_len;

    return 0;
}

int xqc_http3_ringdata_out_queue(xqc_http3_ringdata *rdata, uint64_t start_index, size_t data_len){

    size_t total_len = data_len+1;
    if(rdata->used_start != start_index || rdata->used < total_len){
        return -1;
    }

    //uint8_t *data = rdata->buf + (rdata->start_index)&(rdata->mask);
    rdata->used_start += total_len;

    rdata->used -= total_len;
    return 0;
}

//return 0 if equel, else return -1
int xqc_http3_ringdata_cmp(xqc_http3_ringdata *rdata, size_t start_index, uint8_t * data, size_t data_len){

    if(data_len > rdata->capacity){
        return -1; //impossible
    }
    size_t read_index = (start_index) & (rdata->mask);
    size_t end = read_index + data_len;
    int ret = 0;
    if(end <= rdata->capacity){
        ret = memcmp(rdata->buf + read_index, data, data_len);
    }else{
        if(memcmp(rdata->buf + read_index, data, rdata->capacity - read_index) == 0  &&
                memcmp(rdata->buf, data + rdata->capacity - read_index, end - rdata->capacity) == 0){

            ret = 0;
        }else{
            ret = -1;
        }
    }
    return ret;
}
