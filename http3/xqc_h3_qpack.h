#ifndef __XQC_H3_QPACK_H__
#define __XQC_H3_QPACK_H__

#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "common/xqc_list.h"
#include "common/xqc_config.h"
#include "common/xqc_str.h"
#include "xqc_h3_ringbuf.h"
#include "xqc_h3_qpack_huffman.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QPACK_MAX_TABLE_CAPACITY (16*1024)
#define DEFAULT_MAX_DTABLE_SIZE (4*1024)
#define DEFAULT_QPACK_BLOCK_STREAM (64)
#define DEFAULT_QPACK_HASH_TABLE_SIZE (8*1024)

typedef struct xqc_h3_stream_s xqc_h3_stream_t;
#define XQC_HTTP3_QPACK_INT_MAX ((1ull << 62) - 1)
#define XQC_HTTP3_QPACK_ENTRY_OVERHEAD 32

#define XQC_VAR_BUF_INIT_SIZE 256
#define XQC_VAR_INT_LEN 16
#define XQC_MAX_SIZE_T ((size_t)(-1))
#define XQC_MAX_UINT64 (0xFFFFFFFFFFFFFFFF)

#define XQC_HTTP3_QPACK_MAX_VALUELEN (16*1024) //16K enough? //修改成配置项
#define XQC_HTTP3_QPACK_MAX_NAMELEN 256
#define XQC_HTTP3_QPACK_MAX_NAME_BUFLEN (XQC_HTTP3_QPACK_MAX_NAMELEN + 1)
#define XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN (XQC_HTTP3_QPACK_MAX_VALUELEN + 1)

typedef enum {
    XQC_HTTP3_QPACK_ES_STATE_OPCODE = 0,
    XQC_HTTP3_QPACK_ES_STATE_READ_INDEX,
    XQC_HTTP3_QPACK_ES_STATE_CHECK_NAME_HUFFMAN,
    XQC_HTTP3_QPACK_ES_STATE_READ_NAMELEN,
    XQC_HTTP3_QPACK_ES_STATE_READ_NAME_HUFFMAN,
    XQC_HTTP3_QPACK_ES_STATE_READ_NAME,
    XQC_HTTP3_QPACK_ES_STATE_CHECK_VALUE_HUFFMAN,
    XQC_HTTP3_QPACK_ES_STATE_READ_VALUELEN,
    XQC_HTTP3_QPACK_ES_STATE_READ_VALUE_HUFFMAN,
    XQC_HTTP3_QPACK_ES_STATE_READ_VALUE,
}xqc_http3_qpack_encoder_stream_state;

typedef enum{
    XQC_HTTP3_QPACK_DS_STATE_OPCODE = 0,
    XQC_HTTP3_QPACK_DS_STATE_READ_NUMBER,
}xqc_http3_qpack_decoder_stream_state;

typedef enum{
    XQC_HTTP3_QPACK_DS_OPCODE_ICNT_INCREMENT = 0,
    XQC_HTTP3_QPACK_DS_OPCODE_HEADER_ACK,
    XQC_HTTP3_QPACK_DS_OPCODE_STREAM_CANCEL
}xqc_http3_qpack_decoder_stream_opcode;



/* xqc_http3_qpack_encoder_stream_opcode is a set of opcodes used in
   encoder stream. */
typedef enum {
    XQC_HTTP3_QPACK_ES_OPCODE_INSERT_INDEXED = 0,
    XQC_HTTP3_QPACK_ES_OPCODE_INSERT,
    XQC_HTTP3_QPACK_ES_OPCODE_DUPLICATE,
    XQC_HTTP3_QPACK_ES_OPCODE_SET_DTABLE_CAP,
} xqc_http3_qpack_encoder_stream_opcode;

typedef enum {
    XQC_HTTP3_NV_FLAG_NONE = 0, // indicates no flag set.
    XQC_HTTP3_NV_FLAG_NEVER_INDEX = 0x01, //indicates that this name/value pair must not be indexed.  Other implementation calls this bit as "sensitive".

    XQC_HTTP3_NV_FLAG_NO_COPY_NAME = 0x02, // is set solely by application.  If this flag is set, the library does not make a copy of header field name.  This could improve performance.
    XQC_HTTP3_NV_FLAG_NO_COPY_VALUE = 0x04, //is set solely by application.  If this flag is set, the library does not make a copy of header field value
}xqc_http3_nv_flag_t;

typedef enum{

    //XQC_HTTP3_QPACK_INDEXING_MODE_LITERAL means that header field should not be inserted into dynamic table
    XQC_HTTP3_QPACK_INDEXING_MODE_LITERAL = 0,
    //XQC_HTTP3_QPACK_INDEXING_MODE_STORE means header field can be inserted into dynamic table
    XQC_HTTP3_QPACK_INDEXING_MODE_STORE,
    //XQc_HTTP3_QPACK_INDEXING_MODE_NEVER means that header field should not be inserted into dynamic table and this must be true for all forwarding paths
    XQC_HTTP3_QPACK_INDEXING_MODE_NEVER,

}xqc_http3_qpack_indexing_mode;


/* xqc_http3_qpack_request_stream_state is a set of states for request
   stream decoding. */
typedef enum {
    XQC_HTTP3_QPACK_RS_STATE_RICNT = 0,
    XQC_HTTP3_QPACK_RS_STATE_DBASE_SIGN,
    XQC_HTTP3_QPACK_RS_STATE_DBASE,
    XQC_HTTP3_QPACK_RS_STATE_OPCODE,
    XQC_HTTP3_QPACK_RS_STATE_READ_INDEX,
    XQC_HTTP3_QPACK_RS_STATE_CHECK_NAME_HUFFMAN,
    XQC_HTTP3_QPACK_RS_STATE_READ_NAMELEN,
    XQC_HTTP3_QPACK_RS_STATE_READ_NAME_HUFFMAN,
    XQC_HTTP3_QPACK_RS_STATE_READ_NAME,
    XQC_HTTP3_QPACK_RS_STATE_CHECK_VALUE_HUFFMAN,
    XQC_HTTP3_QPACK_RS_STATE_READ_VALUELEN,
    XQC_HTTP3_QPACK_RS_STATE_READ_VALUE_HUFFMAN,
    XQC_HTTP3_QPACK_RS_STATE_READ_VALUE,
    XQC_HTTP3_QPACK_RS_STATE_BLOCKED,
} xqc_http3_qpack_request_stream_state;

/* xqc_http3_qpack_request_stream_opcode is a set of opcodes used in
   request stream. */
typedef enum {
    XQC_HTTP3_QPACK_RS_OPCODE_INDEXED = 0,
    XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_PB,
    XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME,
    XQC_HTTP3_QPACK_RS_OPCODE_INDEXED_NAME_PB,
    XQC_HTTP3_QPACK_RS_OPCODE_LITERAL,
} xqc_http3_qpack_request_stream_opcode;

typedef struct xqc_qpack_ring_nv{
    size_t      name_index; //uint64
    size_t      name_len;
    size_t      value_index;
    size_t      value_len;
}xqc_qpack_ring_nv_t;

typedef struct xqc_http3_qpack_entry{
    xqc_list_head_t head_list;
    xqc_qpack_ring_nv_t nv;
    xqc_http3_nv_flag_t flag;
    uint64_t absidx;
    uint64_t sum; //
    //uint8_t draining;
    //uint8_t ack_flag;
}xqc_http3_qpack_entry;

typedef struct xqc_qpack_find_result{
    xqc_http3_qpack_entry * name_entry;
    xqc_http3_qpack_entry * entry;

}xqc_qpack_find_result;

typedef struct xqc_qpack_static_find_result{
    int     name_absidx; //name match only
    int     absidx; //name and value match
}xqc_qpack_static_find_result;


typedef struct xqc_qpack_hash_table{
    xqc_list_head_t * list;
    size_t element_count;
}xqc_qpack_hash_table_t;


typedef struct {
    xqc_http3_ringbuf   dtable;
    xqc_http3_ringdata  dtable_data;
    //size_t hard_max_dtable_size;
    uint64_t max_table_capacity;
    uint64_t max_dtable_size; // max_dtable_size is the effective maximum size of dynamic table, the same as ringdata capacity.
    uint64_t max_blocked;
    uint64_t next_absidx;

    uint64_t dtable_size; //the dynamic table size
    uint64_t dtable_sum;

}xqc_http3_qpack_context;


typedef struct xqc_qpack_static_table_entry
{
    char        *name;
    char        *value;
    size_t      name_len;
    size_t      value_len;
}xqc_qpack_static_table_entry;



typedef struct xqc_var_buf{
    size_t  capacity;
    size_t  used_len;
    char    data[];
}xqc_var_buf_t;

typedef struct {
    //char * name;//?
    //char * value;//?
    //xqc_var_string_t * name;
    // xqc_var_string_t * value;

    xqc_var_buf_t *name;
    xqc_var_buf_t *value;
    uint64_t left;
    size_t prefix;
    size_t shift;
    size_t absidx;
    uint8_t never;
    uint8_t dynamic;
    uint8_t huffman_encoded;
    xqc_http3_qpack_huffman_decode_context huffman_ctx;
}xqc_http3_qpack_read_state;
//读取未完成的时候，如变成整数、name,等数据完全时再继续读
//读取一个name-value对未完成时，不继续解码，

typedef struct xqc_qpack_decoder_block_stream{
    xqc_list_head_t  head_list;
    uint64_t        ricnt;
    xqc_h3_stream_t *h3_stream;
    uint64_t    stream_id;
}xqc_qpack_decoder_block_stream_t;

typedef struct xqc_qpack_unack_header_block{ //block means header block
    xqc_list_head_t  header_block_list;
    xqc_list_head_t  stream_in_list;
    size_t      min_rcnt;
    size_t      max_rcnt;
    uint64_t    stream_id;
}xqc_qpack_unack_header_block;



typedef struct xqc_http3_qpack_stream_context {
    xqc_list_head_t block_list;
    /* state is a current state of reading request stream. */
    xqc_http3_qpack_request_stream_state state;
    /* rstate is a set of intermediate state which are used to process
       request stream. */
    xqc_http3_qpack_read_state rstate;
    /* opcode is a request stream opcode being processed. */
    xqc_http3_qpack_request_stream_opcode opcode;
    int64_t stream_id;
    /* ricnt is Required Insert Count to decode this header block. */
    size_t ricnt;
    /* base is Base in Header Block Prefix. */
    size_t base;
    /* dbase_sign is the delta base sign in Header Block Prefix. */
    int dbase_sign;
}xqc_http3_qpack_stream_context;


typedef struct xqc_http3_qpack_decoder{

    xqc_http3_qpack_context ctx;

    //state is a current state of reading encoder stream
    xqc_http3_qpack_encoder_stream_state state;
    xqc_http3_qpack_encoder_stream_opcode opcode;
    xqc_http3_qpack_read_state rstate;

    size_t written_icnt;
    char    *name_buf;
    char    *value_buf;
    xqc_h3_conn_t * h3_conn; //for log
}xqc_http3_qpack_decoder;

typedef xqc_http3_qpack_decoder xqc_http3_qpack_decoder_t;


typedef struct xqc_http3_qpack_encoder{

    xqc_list_head_t         unack_stream_head;
    xqc_http3_qpack_context ctx;
    xqc_http3_qpack_decoder_stream_state state;
    xqc_http3_qpack_decoder_stream_opcode opcode;
    xqc_http3_qpack_read_state rstate;

    size_t krcnt;

    xqc_qpack_hash_table_t dtable_hash;

    //size_t min_dtable_update;// min_dtable_update is the minimum dynamic table size required.
    size_t last_max_dtable_update; //last_max_dtable_update is the dynamic table size last requested.

    uint8_t flags;
    char    *name_buf;
    char    *value_buf;
    xqc_h3_conn_t * h3_conn; //for log
}xqc_http3_qpack_encoder;


typedef struct xqc_var_string{
    size_t strlen; //
    char data[];
}xqc_var_string_t;


typedef struct xqc_qpack_name_value{
    xqc_var_string_t * name;
    xqc_var_string_t * value;
    uint8_t  flag;
}xqc_qpack_name_value_t;




/* xqc_http3_qpack_encoder_flag is a set of flags used by
   xqc_http3_qpack_encoder. */
typedef enum {
    XQC_HTTP3_QPACK_ENCODER_FLAG_NONE = 0x00,
    /* XQC_HTTP3_QPACK_ENCODER_FLAG_PENDING_SET_DTABLE_CAP indicates that
       Set Dynamic Table Capacity is required. */
    XQC_HTTP3_QPACK_ENCODER_FLAG_PENDING_SET_DTABLE_CAP = 0x01,
} xqc_http3_qpack_encoder_flag;


/**
 * @enum
 *
 * :type:`xqc_http3_qpack_decode_flag` is a set of flags for decoder.
 */
typedef enum {
    /**
     * :enum:`XQC_HTTP3_QPACK_DECODE_FLAG_NONE` indicates that no flag
     * set.
     */
    XQC_HTTP3_QPACK_DECODE_FLAG_NONE,
    /**
     * :enum:`XQC_HTTP3_QPACK_DECODE_FLAG_EMIT` indicates that a header
     * field is successfully decoded.
     */
    XQC_HTTP3_QPACK_DECODE_FLAG_EMIT = 0x01,
    /**
     * :enum:`XQC_HTTP3_QPACK_DECODE_FLAG_FINAL` indicates that all header
     * fields have been decoded.
     */
    XQC_HTTP3_QPACK_DECODE_FLAG_FINAL = 0x02,
    /**
     * :enum:`XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED` indicates that decoding
     * has been blocked.
     */
    XQC_HTTP3_QPACK_DECODE_FLAG_BLOCKED = 0x04
} xqc_http3_qpack_decode_flag;


ssize_t xqc_http3_stream_write_header_block(xqc_h3_stream_t *qenc_stream ,xqc_h3_stream_t *stream, xqc_http3_qpack_encoder * encoder,
        xqc_http_headers_t * headers, int fin);
ssize_t xqc_http3_qpack_decoder_read_request_header(xqc_http3_qpack_decoder *decoder, xqc_http3_qpack_stream_context *sctx,
        xqc_qpack_name_value_t *nv, uint8_t *pflags, uint8_t *src, size_t srclen, int fin);

int xqc_http3_qpack_stream_context_init(xqc_http3_qpack_stream_context *sctx, int64_t stream_id);
void xqc_http3_qpack_stream_context_free(xqc_http3_qpack_stream_context * sctx);
void xqc_qpack_name_value_free(xqc_qpack_name_value_t *nv);

ssize_t xqc_http3_qpack_decoder_read_encoder(xqc_h3_conn_t * h3_conn, uint8_t * src, size_t srclen, int *check_block_flag);

ssize_t xqc_http3_qpack_encoder_read_decoder(xqc_h3_conn_t * h3_conn, uint8_t * src, size_t srclen);

int xqc_http3_qpack_encoder_init(xqc_http3_qpack_encoder *qenc, uint64_t max_table_capacity, uint64_t max_dtable_size,
        uint64_t max_blocked, size_t hash_table_size, xqc_h3_conn_t * h3_conn);
int xqc_http3_qpack_decoder_init(xqc_http3_qpack_decoder *qdec, uint64_t max_table_capacity, uint64_t max_dtable_size, uint64_t max_blocked, xqc_h3_conn_t * h3_conn);

int xqc_qpack_decoder_block_stream_check_and_process(xqc_h3_conn_t *h3_conn, uint64_t absidx);
int xqc_http3_qpack_decoder_write_insert_count_increment(xqc_h3_stream_t * qdec_stream, size_t insert_count);


int xqc_http3_handle_header_data_streaming(xqc_h3_conn_t *h3_conn,  xqc_h3_stream_t * h3_stream, char * data, size_t len, uint8_t fin_flag);


int xqc_http3_qpack_encoder_free(xqc_http3_qpack_encoder *qenc);
void xqc_http3_qpack_decoder_free(xqc_http3_qpack_decoder *qdec);
int xqc_http3_qpack_hash_find(xqc_qpack_hash_table_t * table, xqc_http3_ringdata *rdata, char * name, size_t name_len, char *value, size_t value_len, xqc_qpack_find_result *result);
int xqc_http_headers_realloc_buf(xqc_http_headers_t *headers, size_t capacity);
#endif
