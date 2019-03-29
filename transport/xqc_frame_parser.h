
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_frame.h"
#include "xqc_packet_in.h"

/**
 * generate stream frame
 * @param written_size output size of the payload been written
 * @return size of stream frame
 */
int xqc_gen_stream_frame(unsigned char *dst_buf, size_t dst_buf_len,
                         xqc_stream_id_t stream_id, size_t offset, uint8_t fin,
                         const unsigned char *payload, size_t size, size_t *written_size);

int xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

int xqc_parse_frames(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
