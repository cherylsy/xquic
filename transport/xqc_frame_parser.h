
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_frame.h"
#include "xqc_packet_in.h"
#include "xqc_packet_out.h"
#include "xqc_recv_record.h"

/**
 * generate stream frame
 * @param written_size output size of the payload been written
 * @return size of stream frame
 */
int xqc_gen_stream_frame(unsigned char *dst_buf, size_t dst_buf_len,
                         xqc_stream_id_t stream_id, size_t offset, uint8_t fin,
                         const unsigned char *payload, size_t size, size_t *written_size);

int xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_gen_crypto_frame(unsigned char *dst_buf, size_t dst_buf_len, size_t offset,
                     const unsigned char *payload, size_t payload_size, size_t *written_size);

int xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

void xqc_gen_padding_frame(xqc_packet_out_t *packet_out);

int xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_gen_ack_frame(xqc_connection_t *conn, unsigned char *dst_buf, size_t dst_buf_len, xqc_msec_t now, int ack_delay_exponent,
                      xqc_recv_record_t *recv_record, int *has_gap, xqc_packet_number_t *largest_ack);

int xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info);

#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
