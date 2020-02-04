#ifndef __XQC_H3_RINGBUF_H__
#define __XQC_H3_RINGBUF_H__
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf; //buffer points
    size_t nmemb; //number of elements can be stored
    size_t size; //size of each element
    size_t first; //offset to the first element
    size_t len; // number of elements actually stored
}xqc_http3_ringbuf;


typedef struct{
    uint8_t *buf;
    size_t capacity;  //total capacity
    size_t mask;  //for absolute index to relative offset
    uint64_t used; //already used size
    uint64_t used_start; //data start absolute index
    uint64_t free_start; //free space absolute index

}xqc_http3_ringdata;

int xqc_http3_ringbuf_init(xqc_http3_ringbuf * rb, size_t nmemb, size_t size);
size_t xqc_http3_ringbuf_len(xqc_http3_ringbuf *rb);
void * xqc_http3_ringbuf_get(xqc_http3_ringbuf *rb, size_t offset);
void * xqc_http3_ringbuf_push_front(xqc_http3_ringbuf * rb);
void * xqc_http3_ringbuf_push_back(xqc_http3_ringbuf * rb);
void xqc_http3_ringbuf_pop_front(xqc_http3_ringbuf *rb);
void xqc_http3_ringbuf_pop_back(xqc_http3_ringbuf *rb);
int xqc_http3_ringbuf_full(xqc_http3_ringbuf *rb);

int xqc_http3_ringdata_init(xqc_http3_ringdata *rdata, size_t memsize);
uint64_t xqc_get_http3_ringdata_free_start(xqc_http3_ringdata *rdata);
int xqc_http3_ringdata_copy_data(xqc_http3_ringdata *rdata, size_t abs_index, size_t data_len, uint8_t * buf, size_t buf_len);
size_t xqc_http3_ringdata_get_rel_index(xqc_http3_ringdata * rdata, size_t abs_index);
int xqc_http3_ringdata_in_queue(xqc_http3_ringdata *rdata, size_t * abs_index, uint8_t * data, size_t data_len);
int xqc_http3_ringdata_out_queue(xqc_http3_ringdata *rdata, uint64_t start_index, size_t data_len);
int xqc_http3_ringdata_cmp(xqc_http3_ringdata *rdata, size_t start_index, uint8_t * data, size_t data_len);
int xqc_http3_ringdata_copy_data_to_buf(xqc_http3_ringdata *rdata, size_t abs_index, size_t data_len, uint8_t * buf, size_t mask);

void xqc_http3_ringdata_free(xqc_http3_ringdata *rdata);
void xqc_http3_ringbuf_free(xqc_http3_ringbuf *rb);
#endif
