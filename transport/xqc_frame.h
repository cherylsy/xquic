#ifndef _XQC_FRAME_H_INCLUDED_
#define _XQC_FRAME_H_INCLUDED_

#include "../include/xquic_typedef.h"

typedef enum {
    XQC_FRAME_PADDING,
    XQC_FRAME_PING,
    XQC_FRAME_ACK,
    XQC_FRAME_RESET_STREAM,
    XQC_FRAME_STOP_SENDING,
    XQC_FRAME_CRYPTO,
    XQC_FRAME_NEW_TOKEN,
    XQC_FRAME_STREAM,
    XQC_FRAME_MAX_DATA,
    XQC_FRAME_MAX_STREAM_DAT,
    XQC_FRAME_MAX_STREAMS,
    XQC_FRAME_DATA_BLOCKED,
    XQC_FRAME_STREAM_DATA_BLOCKED,
    XQC_FRAME_STREAMS_BLOCKED,
    XQC_FRAME_NEW_CONNECTION_ID,
    XQC_FRAME_RETIRE_CONNECTION_ID,
    XQC_FRAME_PATH_CHALLENGE,
    XQC_FRAME_PATH_RESPONSE,
    XQC_FRAME_CONNECTION_CLOSE,
    XQC_FRAME_Extension,
    XQC_FRAME_NUM,
} xqc_frame_type_t;

typedef enum {
    XQC_FRAME_BIT_PADDING           = 1 << XQC_FRAME_PADDING,
    XQC_FRAME_BIT_PING              = 1 << XQC_FRAME_PING,
    XQC_FRAME_BIT_ACK               = 1 << XQC_FRAME_ACK,
    XQC_FRAME_BIT_RESET_STREAM      = 1 << XQC_FRAME_RESET_STREAM,
    XQC_FRAME_BIT_STOP_SENDING      = 1 << XQC_FRAME_STOP_SENDING,
    XQC_FRAME_BIT_CRYPTO            = 1 << XQC_FRAME_CRYPTO,
    XQC_FRAME_BIT_NEW_TOKEN         = 1 << XQC_FRAME_NEW_TOKEN,
    XQC_FRAME_BIT_STREAM            = 1 << XQC_FRAME_STREAM,
    XQC_FRAME_BIT_MAX_DATA          = 1 << XQC_FRAME_MAX_DATA,
    XQC_FRAME_BIT_MAX_STREAM_DAT    = 1 << XQC_FRAME_MAX_STREAM_DAT,
    XQC_FRAME_BIT_MAX_STREAMS       = 1 << XQC_FRAME_MAX_STREAMS,
    XQC_FRAME_BIT_DATA_BLOCKED      = 1 << XQC_FRAME_DATA_BLOCKED,
    XQC_FRAME_BIT_STREAM_DATA_BLOCKED = 1 << XQC_FRAME_STREAM_DATA_BLOCKED,
    XQC_FRAME_BIT_STREAMS_BLOCKED   = 1 << XQC_FRAME_STREAMS_BLOCKED,
    XQC_FRAME_BIT_NEW_CONNECTION_ID = 1 << XQC_FRAME_NEW_CONNECTION_ID,
    XQC_FRAME_BIT_RETIRE_CONNECTION_ID = 1 << XQC_FRAME_RETIRE_CONNECTION_ID,
    XQC_FRAME_BIT_PATH_CHALLENGE    = 1 << XQC_FRAME_PATH_CHALLENGE,
    XQC_FRAME_BIT_PATH_RESPONSE     = 1 << XQC_FRAME_PATH_RESPONSE,
    XQC_FRAME_BIT_CONNECTION_CLOSE  = 1 << XQC_FRAME_CONNECTION_CLOSE,
    XQC_FRAME_BIT_Extension         = 1 << XQC_FRAME_Extension,
    XQC_FRAME_BIT_NUM               = 1 << XQC_FRAME_NUM,
} xqc_frame_type_bit_t;

/* Put one STREAM frame */
typedef struct xqc_stream_frame_s {
    unsigned char   *data;
    unsigned        data_length;
    uint64_t        data_offset;
    unsigned char   fin;
    xqc_stream_id_t stream_id;
} xqc_stream_frame_t;

unsigned int
xqc_stream_frame_header_size (xqc_stream_id_t stream_id, uint64_t offset, size_t length);

unsigned int
xqc_crypto_frame_header_size (uint64_t offset, size_t length);

#endif /* _XQC_FRAME_H_INCLUDED_ */
