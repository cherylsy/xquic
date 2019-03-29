
#ifndef _XQC_PACKET_PARSER_H_INCLUDED_
#define _XQC_PACKET_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_packet_in.h"

int xqc_gen_short_packet_header (unsigned char *dst_buf, size_t dst_buf_size,
                             unsigned char *dcid, unsigned int dcid_len,
                             unsigned char packet_number_bits, xqc_packet_number_t packet_number);

int xqc_parse_packet_header (xqc_packet_in_t *packet_in);

int xqc_parse_short_packet_header (xqc_packet_in_t *packet_in);

int xqc_parse_long_packet_header (xqc_packet_in_t *packet_in);

#endif /* _XQC_PACKET_PARSER_H_INCLUDED_ */
