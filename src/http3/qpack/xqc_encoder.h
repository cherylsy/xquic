/**
 * @file xqc_encoder.h
 * @brief encoder is responsible for:
 * 1. encode http headers into encoded field section
 * 2. respond to decoder instructions
 */
#ifndef _XQC_ENCODER_H_
#define _XQC_ENCODER_H_

#include "src/http3/qpack/xqc_qpack_defs.h"
#include "src/http3/qpack/stable/xqc_stable.h"
#include "src/http3/qpack/dtable/xqc_dtable.h"

typedef struct xqc_encoder_s xqc_encoder_t;



xqc_encoder_t *
xqc_encoder_create(xqc_log_t *log);

void
xqc_encoder_destroy(xqc_encoder_t *enc);


/**
 * @brief encode headers to filed section
 * @return xqc_int_t 
 */
xqc_int_t
xqc_encoder_enc_headers(xqc_encoder_t *enc, xqc_var_buf_t *efs,
    xqc_var_buf_t *ins, uint64_t stream_id, xqc_http_headers_t *hdrs);

xqc_int_t
xqc_encoder_section_ack(xqc_encoder_t *enc, uint64_t stream_id);

xqc_int_t
xqc_encoder_cancel_stream(xqc_encoder_t *enc, uint64_t stream_id);

xqc_int_t
xqc_encoder_increase_known_rcvd_count(xqc_encoder_t *enc, uint64_t increment);

xqc_int_t
xqc_encoder_set_max_dtable_cap(xqc_encoder_t *enc, size_t max_cap);

xqc_int_t
xqc_encoder_set_dtable_cap(xqc_encoder_t *enc, size_t cap);

xqc_int_t
xqc_encoder_set_max_blocked_stream(xqc_encoder_t *enc, size_t max_blocked_stream);

void
xqc_encoder_set_insert_limit(xqc_encoder_t *enc, double nlimit, double vlimit);

#endif
