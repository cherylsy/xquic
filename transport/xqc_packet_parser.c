#include <string.h>
#include "xqc_packet_parser.h"
#include "xqc_cid.h"

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|0|1|S|R|R|K|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Destination Connection ID (0..144)           ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Packet Number (8/16/24/32)              ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Protected Payload (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                  Short Header Packet Format
*/

#define xqc_packet_number_bits2len(b) ((b) + 1)


static int
xqc_write_packet_number (unsigned char *buf, xqc_packet_number_t packet_number,
                         unsigned char packet_number_bits)
{
    unsigned char *p = buf;
    unsigned int packet_number_len = xqc_packet_number_bits2len(packet_number_bits);

    if (packet_number_len == 4) {
        *buf++ = packet_number >> 24;
    }
    if (packet_number_len >= 3) {
        *buf++ = packet_number >> 16;
    }
    if (packet_number_len >= 2) {
        *buf++ = packet_number >> 8;
    }
    *buf++ = packet_number;

    return buf - p;
}


int
xqc_gen_short_packet_header (unsigned char *dst_buf, size_t dst_buf_size,
                      unsigned char *dcid, unsigned int dcid_len,
                      unsigned char packet_number_bits, xqc_packet_number_t packet_number)
{
    unsigned char spin_bit = 0x01;
    unsigned char reserved_bits = 0x00;
    unsigned char key_phase_bit = 0x00;

    unsigned int packet_number_len = xqc_packet_number_bits2len(packet_number_bits);
    unsigned int need = 1 + dcid_len + packet_number_len;


    if (need > dst_buf_size) {
        return -1;
    }

    dst_buf[0] = 0x40 | spin_bit << 5 | reserved_bits << 3 | key_phase_bit << 2 | packet_number_bits;

    if (dcid_len) {
        memcpy(dst_buf + 1, dcid, dcid_len);
    }

    xqc_write_packet_number(dst_buf + 1 + dcid_len, packet_number, packet_number_bits);


    return need;
}

int
xqc_parse_packet_header (xqc_packet_in_t *packet_in)
{
    if (packet_in->pi_buf_size <= 0) {
        return -1;
    }
    if (packet_in->pi_buf[0] & 0x80) {
        return xqc_parse_long_packet_header(packet_in);
    }
    else {
        return xqc_parse_short_packet_header(packet_in);
    }
}

/* Parse xqc_packet_in_t's buff, get xqc_packet_t */
int
xqc_parse_short_packet_header (xqc_packet_in_t *packet_in)
{
    unsigned char firt_byte = packet_in->pi_buf[0];

    unsigned char packno_bits = firt_byte & 0x03;
    unsigned char packno_len = packno_bits + 1;

    unsigned char cid_len = XQC_DEFAULT_CID_LEN; //TODO: parse from long header

    unsigned char header_size = 1 + packno_len + cid_len;

    memcpy(packet_in->pi_pkt.pkt_dcid.cid_buf, packet_in->pi_buf + 1, cid_len);
    packet_in->pi_pkt.pkt_dcid.cid_len = cid_len;

    packet_in->pi_pkt.pkt_type = PTYPE_SHORT_HEADER;
    packet_in->pi_pkt.pkt_pns = PNS_01RTT;
    //pi_pkt.pkt_num //TODO: need decrypted

    packet_in->pi_header_size = header_size;
    packet_in->processed_offset = header_size;
    return 0;
}

int
xqc_parse_long_packet_header (xqc_packet_in_t *packet_in)
{

    return 0;
}