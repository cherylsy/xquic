#include <string.h>
#include "xqc_packet_parser.h"
#include "xqc_cid.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_packet_out.h"


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

unsigned
xqc_long_packet_header_size (unsigned char dcid_len, unsigned char scid_len, unsigned char token_len,
                             xqc_packet_number_t packet_number, unsigned char pktno_bits, xqc_pkt_type_t type)
{
    return 1 //first byte
           + 4 //version
           + 1 //DCIL(4)|SCIL(4)
           + dcid_len
           + scid_len
           + (type == XQC_PTYPE_INIT ? xqc_vint_len_by_val(token_len) + token_len : 0)
           + 2 //Length (i)
           + xqc_packet_number_bits2len(pktno_bits);


}

void
xqc_long_packet_update_length (xqc_packet_out_t *packet_out)
{
    if (packet_out->po_pkt.pkt_type == XQC_PTYPE_SHORT_HEADER) {
        return;
    }

    unsigned length = packet_out->po_buf + packet_out->po_used_size - packet_out->plength - 2;

    xqc_vint_write(packet_out->plength, length, 0x01, 2);
}

int
xqc_gen_long_packet_header (xqc_packet_out_t *packet_out,
                            unsigned char *dcid, unsigned char dcid_len,
                            unsigned char *scid, unsigned char scid_len,
                            unsigned char *token, unsigned char token_len,
                            unsigned ver, xqc_pkt_type_t type,
                            xqc_packet_number_t packet_number, unsigned char pktno_bits)
{
    unsigned char *dst_buf = packet_out->po_buf;
    size_t dst_buf_size = packet_out->po_buf_size - packet_out->po_used_size;

    unsigned int need = xqc_long_packet_header_size(dcid_len, scid_len, token_len, packet_number, pktno_bits, type);

    unsigned char *begin = dst_buf;
    unsigned char bits;
    unsigned int vlen;

    if (need > dst_buf_size) {
        return -1;
    }

    if (dcid_len < 3 || scid_len < 3) {
        return -1;
    }

    unsigned char first_byte = 0xC0;
    first_byte |= type << 4;
    first_byte |= pktno_bits;
    *dst_buf++ = first_byte;

    memcpy(dst_buf, &ver, sizeof(ver));
    dst_buf += sizeof(ver);

    *dst_buf = (dcid_len - 3) << 4;
    *dst_buf |= scid_len - 3;
    dst_buf++;

    memcpy(dst_buf, dcid, dcid_len);
    dst_buf += dcid_len;
    memcpy(dst_buf, scid, scid_len);
    dst_buf += scid_len;

    if (type == XQC_PTYPE_INIT) {
        bits = xqc_vint_get_2bit(token_len);
        vlen = xqc_vint_len(bits);
        xqc_vint_write(dst_buf, token_len, bits, vlen);
        dst_buf += vlen;
        if (token > 0) {
            memcpy(dst_buf, token, token_len);
            dst_buf += token_len;
        }
    }

    packet_out->plength = dst_buf;
    dst_buf += 2; //Length update when write frame

    dst_buf += xqc_write_packet_number(dst_buf, packet_number, pktno_bits);


    return dst_buf - begin;

}

int
xqc_parse_packet_header (xqc_packet_in_t *packet_in)
{
    if (packet_in->buf_size <= 0) {
        return -1;
    }
    if (packet_in->buf[0] & 0x80) {
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
    unsigned char firt_byte = packet_in->buf[0];

    unsigned char packno_bits = firt_byte & 0x03;
    unsigned char packno_len = packno_bits + 1;

    unsigned char cid_len = XQC_DEFAULT_CID_LEN; //TODO: parse from long header

    unsigned char header_size = 1 + packno_len + cid_len;

    memcpy(packet_in->pi_pkt.pkt_dcid.cid_buf, packet_in->buf + 1, cid_len);
    packet_in->pi_pkt.pkt_dcid.cid_len = cid_len;

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_01RTT;
    //pi_pkt.pkt_num //TODO: need decrypted

    //packet_in->pi_header_size = header_size;
    //packet_in->processed_offset = header_size;
    return 0;
}

int
xqc_parse_long_packet_header (xqc_packet_in_t *packet_in)
{

    return 0;
}
