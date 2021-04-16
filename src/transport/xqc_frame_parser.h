
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_recv_record.h"

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

int xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_stream_frame_t * frame);

void xqc_gen_padding_frame(xqc_packet_out_t *packet_out);

int xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_gen_ping_frame(xqc_packet_out_t *packet_out);

int xqc_parse_ping_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_msec_t now, int ack_delay_exponent,
                      xqc_recv_record_t *recv_record, int *has_gap, xqc_packet_number_t *largest_ack);

int xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info);

int xqc_parse_new_conn_id_frame(xqc_packet_in_t *packet_in);

int xqc_gen_conn_close_frame(xqc_packet_out_t *packet_out, uint64_t err_code, int is_app, int frame_type);

int xqc_parse_conn_close_frame(xqc_packet_in_t *packet_in, uint64_t *err_code);

int xqc_gen_reset_stream_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
                           uint64_t err_code, uint64_t final_size);

int xqc_parse_reset_stream_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
                             uint64_t *err_code, uint64_t *final_size);

int xqc_gen_stop_sending_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
                               uint64_t err_code);

int xqc_parse_stop_sending_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
                                 uint64_t *err_code);

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

int xqc_gen_new_token_frame(xqc_packet_out_t *packet_out, const unsigned char *token, unsigned token_len);

int xqc_parse_new_token_frame(xqc_packet_in_t *packet_in, unsigned char *token, unsigned *token_len);

int xqc_gen_handshake_done_frame(xqc_packet_out_t *packet_out);

int xqc_parse_handshake_done_frame(xqc_packet_in_t *packet_in);

size_t xqc_gen_new_conn_id_frame(xqc_packet_out_t *packet_out, xqc_cid_t *new_cid);

xqc_int_t xqc_parse_new_conn_id_frame(xqc_packet_in_t *packet_in, xqc_cid_t *new_cid);

size_t xqc_gen_path_status_frame(xqc_packet_out_t *packet_out, 
    uint64_t path_id, uint64_t path_status_seq_number,
    uint64_t path_status, uint64_t path_prio);

xqc_int_t xqc_parse_path_status_frame(xqc_packet_in_t *packet_in,
    xqc_connection_t *conn);


#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
