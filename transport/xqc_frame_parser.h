
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_frame.h"
#include "xqc_packet_in.h"
#include "xqc_packet_out.h"
#include "xqc_recv_record.h"
#include "xqc_stream.h"

/**
 * generate stream frame
 * @param written_size output size of the payload been written
 * @return size of stream frame
 */
int xqc_gen_stream_frame(xqc_packet_out_t *packet_out,
                         xqc_stream_id_t stream_id, size_t offset, uint8_t fin,
                         const unsigned char *payload, size_t size, size_t *written_size);

int xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
                           xqc_stream_frame_t *frame, xqc_stream_id_t *stream_id);

int xqc_gen_crypto_frame(xqc_packet_out_t *packet_out, size_t offset,
                     const unsigned char *payload, size_t payload_size, size_t *written_size);

int xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

void xqc_gen_padding_frame(xqc_packet_out_t *packet_out);

int xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_msec_t now, int ack_delay_exponent,
                      xqc_recv_record_t *recv_record, int *has_gap, xqc_packet_number_t *largest_ack);

int xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info);

int xqc_gen_conn_close_frame(xqc_packet_out_t *packet_out, unsigned short err_code, int is_app, int frame_type);

int xqc_parse_conn_close_frame(xqc_packet_in_t *packet_in, unsigned short *err_code);

int xqc_gen_reset_stream_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
                           unsigned short err_code, uint64_t final_size);

int xqc_parse_reset_stream_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
                             unsigned short *err_code, uint64_t *final_size);

int xqc_gen_stop_sending_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
                               unsigned short err_code);

int xqc_parse_stop_sending_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
                                 unsigned short *err_code);

int xqc_gen_data_blocked_frame(xqc_packet_out_t *packet_out, uint64_t data_limit);

int xqc_parse_data_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *data_limit);

int xqc_gen_stream_data_blocked_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

int xqc_parse_stream_data_blocked_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *stream_data_limit);

int xqc_gen_streams_blocked_frame(xqc_packet_out_t *packet_out, uint64_t stream_limit, int bidirectional);

int xqc_parse_streams_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *stream_limit, int *bidirectional);

int xqc_gen_max_data_frame(xqc_packet_out_t *packet_out, uint64_t max_data);

int xqc_parse_max_data_frame(xqc_packet_in_t *packet_in, uint64_t *max_data);

int xqc_gen_max_stream_data_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t max_stream_data);

int xqc_parse_max_stream_data_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *max_stream_data);

int xqc_gen_max_streams_frame(xqc_packet_out_t *packet_out, uint64_t max_streams, int bidirectional);

int xqc_parse_max_streams_frame(xqc_packet_in_t *packet_in, uint64_t *max_streams, int *bidirectional);

#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
