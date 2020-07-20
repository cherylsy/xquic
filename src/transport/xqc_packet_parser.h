
#ifndef _XQC_PACKET_PARSER_H_INCLUDED_
#define _XQC_PACKET_PARSER_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"

#define XQC_PKTNO_BITS 3
#define XQC_LONG_HEADER_LENGTH_BYTE 2

unsigned
xqc_short_packet_header_size (unsigned char dcid_len, unsigned char pktno_bits);

unsigned
xqc_long_packet_header_size (unsigned char dcid_len, unsigned char scid_len, unsigned char token_len,
                             unsigned char pktno_bits, xqc_pkt_type_t type);

int
xqc_write_packet_number (unsigned char *buf, xqc_packet_number_t packet_number,
                         unsigned char packet_number_bits);

int
xqc_gen_short_packet_header (xqc_packet_out_t *packet_out,
                             unsigned char *dcid, unsigned int dcid_len,
                             unsigned char packet_number_bits, xqc_packet_number_t packet_number);

xqc_int_t
xqc_packet_parse_short_header(xqc_connection_t *c,
                              xqc_packet_in_t *packet_in);

void
xqc_long_packet_update_length (xqc_packet_out_t *packet_out);

void
xqc_short_packet_update_dcid(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

int
xqc_gen_long_packet_header (xqc_packet_out_t *packet_out,
                            const unsigned char *dcid, unsigned char dcid_len,
                            const unsigned char *scid, unsigned char scid_len,
                            const unsigned char *token, unsigned token_len,
                            xqc_proto_version_t ver,
                            unsigned char pktno_bits);

xqc_int_t
xqc_packet_parse_long_header(xqc_connection_t *c,
                             xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_initial(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_zero_rtt(xqc_connection_t *c, xqc_packet_in_t *packet_in);

xqc_int_t
xqc_packet_parse_handshake(xqc_connection_t *c, xqc_packet_in_t *packet_in);

int
xqc_gen_retry_packet(unsigned char *dst_buf,
                     const unsigned char *dcid, unsigned char dcid_len,
                     const unsigned char *scid, unsigned char scid_len,
                     const unsigned char *odcid, unsigned char odcid_len,
                     const unsigned char *token, unsigned token_len,
                     unsigned ver);

xqc_int_t
xqc_packet_parse_retry(xqc_connection_t *c, xqc_packet_in_t *packet_in);

#if (XQC_VERSION_NEGOTIATION)
xqc_int_t
xqc_packet_parse_version_negotiation(xqc_connection_t *c, xqc_packet_in_t *packet_in);
#endif

xqc_int_t
xqc_gen_reset_packet(xqc_cid_t *cid, unsigned char *dst_buf);

int
xqc_is_reset_packet(xqc_cid_t *cid, const unsigned char *buf, unsigned buf_size);

int
xqc_packet_decrypt(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

int
xqc_packet_encrypt(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

int
xqc_packet_encrypt_buf(xqc_connection_t *conn, xqc_packet_out_t *packet_out, unsigned char *enc_pkt, size_t *enc_pkt_len);

#endif /* _XQC_PACKET_PARSER_H_INCLUDED_ */
