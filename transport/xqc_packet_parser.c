#include <string.h>
#include "xqc_packet_parser.h"

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

    if (packet_number_len > 4) {
        return -1;
    }
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

    int ret = 0;

    if (need > dst_buf_size) {
        return -1;
    }

    dst_buf[0] = 0x40 | spin_bit << 5 | reserved_bits << 3 | key_phase_bit << 2 | packet_number_bits;

    if (dcid_len) {
        memcpy(dst_buf + 1, dcid, dcid_len);
    }

    ret = xqc_write_packet_number(dst_buf + 1 + dcid_len, packet_number, packet_number_bits);
    if (ret) {
        return ret;
    }

    return need;
}