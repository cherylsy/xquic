#ifndef _XQC_FRAME_H_INCLUDED_
#define _XQC_FRAME_H_INCLUDED_

#include <common/xqc_list.h>
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
    XQC_FRAME_MAX_STREAM_DATA,
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
    XQC_FRAME_BIT_MAX_STREAM_DATA   = 1 << XQC_FRAME_MAX_STREAM_DATA,
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



#define XQC_IS_ACK_ELICITING(types) (types & ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_CONNECTION_CLOSE))

/*
 * Connection close signals, including packets that contain
      CONNECTION_CLOSE frames, are not sent again when packet loss is
      detected, but as described in Section 10.
 */
//TODO: more frames?
#define XQC_CAN_RETRANSMIT(types) (types & ( \
    XQC_FRAME_BIT_RESET_STREAM | \
    XQC_FRAME_BIT_CRYPTO | \
    XQC_FRAME_BIT_STREAM | \
    )) \

#define XQC_CAN_IN_FLIGHT(types) XQC_IS_ACK_ELICITING(types)


const char*
xqc_frame_type_2_str (xqc_frame_type_bit_t type_bit);

unsigned int
xqc_stream_frame_header_size (xqc_stream_id_t stream_id, uint64_t offset, size_t length);

unsigned int
xqc_crypto_frame_header_size (uint64_t offset, size_t length);

xqc_int_t
xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *stream_frame);

xqc_int_t
xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_ack_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_conn_close_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_reset_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_stop_sending_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_stream_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_streams_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_max_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_max_stream_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_max_streams_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_process_new_token_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

#endif /* _XQC_FRAME_H_INCLUDED_ */
