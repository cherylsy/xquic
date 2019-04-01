
#ifndef _XQUIC_TYPEDEF_H_INCLUDED_
#define _XQUIC_TYPEDEF_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

typedef struct xqc_stream_s xqc_stream_t;
typedef struct xqc_connection_s xqc_connection_t;
typedef struct xqc_conn_settings_s xqc_conn_settings_t;
typedef struct xqc_engine_s xqc_engine_t;
typedef struct xqc_conn_callbacks_s xqc_conn_callbacks_t;
typedef struct xqc_random_generator_s xqc_random_generator_t;
typedef struct xqc_client_connection_s xqc_client_connection_t;
typedef struct xqc_id_hash_table_s xqc_id_hash_table_t;
typedef struct xqc_str_hash_table_s xqc_str_hash_table_t;
typedef struct xqc_priority_queue_s xqc_pq_t;
typedef struct xqc_log_s xqc_log_t;
typedef struct xqc_send_ctl_s xqc_send_ctl_t;


typedef uint64_t xqc_msec_t;


typedef uint64_t xqc_packet_number_t;
typedef uint64_t xqc_stream_id_t;

#define XQC_MAX_CID_LEN 18
typedef struct xqc_cid_s
{
    uint8_t    cid_len;
    uint8_t    cid_buf[XQC_MAX_CID_LEN];
} xqc_cid_t;


inline xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src)
{
    dst->cid_len = src->cid_len;
    xqc_memcpy(dst->cid_buf, src->cid_buf, dst->cid_len);
}

inline xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    xqc_memzero(cid->cid_buf, XQC_MAX_CID_LEN);
}


#endif /*_XQUIC_TYPEDEF_H_INCLUDED_*/
