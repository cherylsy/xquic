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
