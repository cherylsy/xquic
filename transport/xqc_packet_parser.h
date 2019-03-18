
#ifndef _XQC_PACKET_PARSER_H_INCLUDED_
#define _XQC_PACKET_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"


int xqc_gen_short_packet_header (unsigned char *dst_buf, size_t dst_buf_size,
                             unsigned char *dcid, unsigned int dcid_len,
                             unsigned char packet_number_bits, xqc_packet_number_t packet_number);

#endif /* _XQC_PACKET_PARSER_H_INCLUDED_ */
