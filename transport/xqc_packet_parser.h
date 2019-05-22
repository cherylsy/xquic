
#ifndef _XQC_PACKET_PARSER_H_INCLUDED_
#define _XQC_PACKET_PARSER_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_packet_in.h"
#include "xqc_packet_out.h"

#define XQC_PKTNO_BITS 3

unsigned
xqc_short_packet_header_size (unsigned char dcid_len, unsigned char pktno_bits);

unsigned
xqc_long_packet_header_size (unsigned char dcid_len, unsigned char scid_len, unsigned char token_len,
                             unsigned char pktno_bits, xqc_pkt_type_t type);
xqc_int_t
xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                               unsigned char *buf, size_t size);

int
xqc_gen_short_packet_header (xqc_packet_out_t *packet_out,
                             unsigned char *dcid, unsigned int dcid_len,
                             unsigned char packet_number_bits, xqc_packet_number_t packet_number);

xqc_int_t
xqc_packet_parse_short_header(xqc_connection_t *c,
                              xqc_packet_in_t *packet_in);

void
xqc_long_packet_update_length (xqc_packet_out_t *packet_out);

int
xqc_gen_long_packet_header (xqc_packet_out_t *packet_out,
                            unsigned char *dcid, unsigned char dcid_len,
                            unsigned char *scid, unsigned char scid_len,
                            unsigned char *token, unsigned char token_len,
                            unsigned ver, xqc_pkt_type_t type,
                            xqc_packet_number_t packet_number, unsigned char pktno_bits);

xqc_int_t
xqc_packet_parse_long_header(xqc_connection_t *c,
                             xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_initial(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_zero_rtt(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_handshake(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_retry(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_version_negotiation(xqc_connection_t *c, xqc_packet_in_t *packet_in);



#endif /* _XQC_PACKET_PARSER_H_INCLUDED_ */
