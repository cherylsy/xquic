#include <string.h>
#include "xqc_packet_parser.h"
#include "xqc_cid.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_packet_out.h"
#include <arpa/inet.h>
#include <common/xqc_algorithm.h>
#include "common/xqc_log.h"
#include "xqc_conn.h"
#include "xqc_packet.h"

#define xqc_packet_number_bits2len(b) ((b) + 1)


xqc_int_t
xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                     unsigned char *buf, size_t size)
{
    unsigned char *pos = NULL;

    if (size <= 0) {
        return XQC_ERROR;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(buf)) {

        /* TODO: fix me, variable length */
        if (size < 1 + XQC_DEFAULT_CID_LEN) {
            return XQC_ERROR;
        }

        xqc_cid_set(dcid, buf + 1, XQC_DEFAULT_CID_LEN);

        return XQC_OK;
    }

    /* long header */
    if (size < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH) {
        return XQC_ERROR;
    }

    pos = buf + 1 + XQC_PACKET_VERSION_LENGTH;
    dcid->cid_len = XQC_PACKET_LONG_HEADER_GET_DCIL(pos);
    scid->cid_len = XQC_PACKET_LONG_HEADER_GET_SCIL(pos);
    pos += 1;

    if (dcid->cid_len) {
        dcid->cid_len += 3;
    }

    if (scid->cid_len) {
        scid->cid_len += 3;
    }

    if (size < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
               + dcid->cid_len + scid->cid_len)
    {
        return XQC_ERROR;
    }

    xqc_memcpy(dcid->cid_buf, pos, dcid->cid_len);
    pos += dcid->cid_len;

    xqc_memcpy(scid->cid_buf, pos, scid->cid_len);
    pos += scid->cid_len;

    return XQC_OK;
}


void
xqc_packet_parse_packet_number(unsigned char *pos,
                               xqc_uint_t packet_number_len,
                               uint64_t *packet_num)
{
    *packet_num = 0;
    for (int i = 0; i < packet_number_len; i++) {
        *packet_num = ((*packet_num) << 8) + (*pos);
        pos++;
    }
}


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
xqc_gen_short_packet_header (xqc_packet_out_t *packet_out,
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

    unsigned char *dst_buf = packet_out->po_buf;
    size_t dst_buf_size = packet_out->po_buf_size - packet_out->po_used_size;

    packet_out->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

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

xqc_int_t
xqc_packet_parse_short_header(xqc_connection_t *c,
                              xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;


    packet_in->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_01RTT;

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) < 1 + XQC_DEFAULT_CID_LEN) {
        return XQC_ERROR;
    }

    /* check fixed bit(0x40) = 1 */
    if ((pos[0] & 0x40) == 0) {
        xqc_log(c->log, XQC_LOG_WARN, "parse short header: fixed bit err");
        return XQC_ERROR;
    }

    xqc_uint_t spin_bit = (pos[0] & 0x20) >> 5;
    xqc_uint_t reserved_bits = (pos[0] & 0x18) >> 3;
    xqc_uint_t key_phase = (pos[0] & 0x04) >> 2;
    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;
    pos += 1;

    xqc_log(c->log, XQC_LOG_DEBUG, "parse short header: spin_bit=%ui, reserved_bits=%ui, key_phase=%ui, packet_number_len=%ui",
            spin_bit, reserved_bits,
            key_phase, packet_number_len);

    /* check dcid */
    xqc_cid_set(&(packet->pkt_dcid), pos, XQC_DEFAULT_CID_LEN);
    pos += XQC_DEFAULT_CID_LEN;
    if (xqc_cid_is_equal(&(packet->pkt_dcid), &c->dcid) != XQC_OK) {
        /* log & ignore */
        xqc_log(c->log, XQC_LOG_WARN, "parse short header: invalid destination cid");
        return XQC_ERROR;
    }

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* protected payload */

    packet_in->pos = pos;

    if (c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
    }


    return XQC_OK;
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

    packet_out->po_pkt.pkt_type = type;

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

    ver = htonl(ver);
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
        if (token_len > 0) {
            memcpy(dst_buf, token, token_len);
            dst_buf += token_len;
        }
    }

    packet_out->plength = dst_buf;
    dst_buf += 2; //Length update when write frame

    dst_buf += xqc_write_packet_number(dst_buf, packet_number, pktno_bits);


    return dst_buf - begin;

}


/*
+-+-+-+-+-+-+-+-+
|1|1| 0 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Token Length (i)                    ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Token (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length (i)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Packet Number (8/16/24/32)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 12: Initial Packet
*/
xqc_int_t
xqc_packet_parse_initial(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;
    ssize_t size = 0;
    uint64_t token_len = 0, payload_len = 0;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|initial|");

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_INIT;

    if (c->conn_state == XQC_CONN_STATE_SERVER_INIT &&
        XQC_PACKET_IN_LEFT_SIZE(packet_in) < XQC_PACKET_INITIAL_MIN_LENGTH) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|initial size too small|%z|",
                XQC_PACKET_IN_LEFT_SIZE(packet_in));
        return XQC_ERROR;
    }

    /* parse packet */
    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;

    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
           + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;

    /* Token Length(i) & Token */
    size = xqc_vint_read(pos, packet_in->last, &token_len);
    if (size < 0 || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + token_len) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|token length err|");
        return XQC_ERROR;
    }
    pos += size;

    /* TODO: check token */
    c->token.len = token_len;
    c->token.data = pos;
    pos += token_len;
    packet_in->pos = pos;

    /* Length(i) */
    size = xqc_vint_read(pos, packet_in->last, &payload_len);
    if (size < 0
        || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + payload_len)
    {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|payload length err|");
        return XQC_ERROR;
    }
    pos += size;

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* decrypt payload */
    //pos += payload_len - packet_number_len; //parse frame时更新

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_initial|success|packe_num=%ui|payload=%ui|", packet->pkt_num, payload_len);
    packet_in->pos = pos;


    return XQC_OK;
}


/*
+-+-+-+-+-+-+-+-+
|1|1| 1 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length (i)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Packet Number (8/16/24/32)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            0-RTT Packet
*/
xqc_int_t
xqc_packet_parse_zero_rtt(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;
    ssize_t size = 0;
    uint64_t payload_len = 0;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|0-RTT|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_0RTT;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_01RTT;

    if ((++c->zero_rtt_count) > XQC_PACKET_0RTT_MAX_COUNT) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_zero_rtt|too many 0-RTT packets|");
        return XQC_ERROR;
    }

    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;

    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
           + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;

    /* Length(i) */
    size = xqc_vint_read(pos, packet_in->last, &payload_len);
    if (size < 0
        || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + payload_len + packet_number_len)
    {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_zero_rtt|payload length err|");
        return XQC_ERROR;
    }

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* decrypt payload */

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_zero_rtt|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;

    return XQC_OK;
}


/*
+-+-+-+-+-+-+-+-+
|1|1| 2 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length (i)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Packet Number (8/16/24/32)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 13: Handshake Protected Packet
*/
xqc_int_t
xqc_packet_parse_handshake(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;
    ssize_t size = 0;
    uint64_t payload_len = 0;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|handshake|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_HSK;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_HSK;

    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;

    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
           + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;

    /* Length(i) */
    size = xqc_vint_read(pos, packet_in->last, &payload_len);
    if (size < 0
        || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + payload_len/* + packet_number_len*/)
    {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_handshake|payload length err|");
        return XQC_ERROR;
    }
    pos += size;

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* decrypt payload */
    //pos += payload_len - packet_number_len; //parse frame时更新


    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_handshake|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;


    return XQC_OK;
}


xqc_int_t
xqc_packet_parse_retry(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|retry|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_RETRY;


    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_retry|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;

    return XQC_OK;
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|  Unused (7) |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Version (32)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DCIL(4)|SCIL(4)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0/32..144)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0/32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Supported Version 1 (32)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   [Supported Version 2 (32)]                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   [Supported Version N (32)]                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                  Figure 11: Version Negotiation Packet
*/


xqc_int_t
xqc_packet_parse_version_negotiation(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|version negotiation|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_VERSION_NEGOTIATION;

    /*让packet_in->pos指向Supported Version列表*/
    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;

    /*至少需要一个support version*/
    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) < XQC_PACKET_VERSION_LENGTH) {
        xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|version negotiation size too small|%z|", XQC_PACKET_IN_LEFT_SIZE(packet_in));
        return XQC_ERROR;
    }

    /*检查dcid & scid已经在外层函数完成*/

    /*check available states*/
    if (c->conn_state != XQC_CONN_STATE_CLIENT_INITIAL_SENT) {
        /* drop packet */
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|invalid state|%i|", (int)c->conn_state);
        return XQC_ERROR;
    }

    /*check conn type*/
    if (c->conn_type != XQC_CONN_TYPE_CLIENT) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|invalid conn_type|%i|", (int)c->conn_type);
        return XQC_ERROR;
    }

    /*check discard vn flag*/
    if (c->discard_vn_flag != 0) {
        packet_in->pos = packet_in->last;
        return XQC_OK;
    }

    /*get Supported Version list*/
    uint32_t supported_version_list[256];
    uint32_t supported_version_count = 0;

    while (XQC_PACKET_IN_LEFT_SIZE(packet_in) >= XQC_PACKET_VERSION_LENGTH) {
        uint32_t version = *(uint32_t*)packet_in->pos;
        if (version) {
            if (xqc_uint32_list_find(supported_version_list, supported_version_count, version) == -1) {
                if (supported_version_count < sizeof(supported_version_list) / sizeof(*supported_version_list)) {
                    supported_version_list[supported_version_count++] = version;
                }
            } else { /*重复版本号*/
                xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|dup version|%i|", version);
            }
        }

        packet_in->pos += XQC_PACKET_VERSION_LENGTH;
    }

    /*客户端当前使用版本跟support version list中的版本一样，忽略该VN包*/
    if (xqc_uint32_list_find(supported_version_list, supported_version_count, c->version) != -1) {
        packet_in->pos = packet_in->last;
        return XQC_OK;
    }

    /*如果客户端不支持任何supported version list的版本，则abort连接尝试*/
    uint32_t *config_version_list = c->engine->config->support_version_list;
    uint32_t config_version_count = c->engine->config->support_version_count;

    uint32_t version_chosen = 0;

    for (uint32_t i = 0; i < supported_version_count; ++i) {
        if (xqc_uint32_list_find(config_version_list, config_version_count, supported_version_list[i]) != -1) {
            version_chosen = supported_version_list[i];
            break;
        }
    }

    if (version_chosen == 0) {
        /*TODO:zuo*/
        /*abort the connection attempt*/
        return XQC_ERROR;
    }

    /*设置客户端版本*/
    c->version = version_chosen;

    /*TODO:zuo 用新的版本号重新连接服务器*/
    xqc_stream_t *stream = c->crypto_stream[XQC_ENC_LEV_INIT];
    if (stream == NULL) {
        return XQC_ERROR;
    }
    xqc_stream_ready_to_write(stream);

    /*设置discard vn flag*/
    c->discard_vn_flag = 1;

    return XQC_OK;
}


/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     Long Header Packet Format
*/

xqc_int_t
xqc_packet_parse_long_header(xqc_connection_t *c,
                             xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t  *packet = &packet_in->pi_pkt;
    xqc_uint_t i;
    xqc_int_t ret = XQC_ERROR;

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH) {
        return XQC_ERROR;
    }

    /* check fixed bit(0x40) = 1 */
    if ((pos[0] & 0x40) == 0) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_long_header|fixed bit err|");
        return XQC_ERROR;
    }

    xqc_uint_t type = (pos[0] & 0x30) >> 4;
    pos++;

    /* TODO: version check */
    uint32_t version = xqc_parse_uint32(pos);
    pos += XQC_PACKET_VERSION_LENGTH;

    /* get dcid & scid */
    xqc_cid_t *dcid = &packet->pkt_dcid;
    xqc_cid_t *scid = &packet->pkt_scid;
    dcid->cid_len = XQC_PACKET_LONG_HEADER_GET_DCIL(pos);
    scid->cid_len = XQC_PACKET_LONG_HEADER_GET_SCIL(pos);
    pos += 1;

    if (dcid->cid_len) {
        dcid->cid_len += 3;
    }

    if (scid->cid_len) {
        scid->cid_len += 3;
    }

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
                                             + dcid->cid_len + scid->cid_len)
    {
        return XQC_ERROR;
    }

    xqc_memcpy(dcid->cid_buf, pos, dcid->cid_len);
    pos += dcid->cid_len;

    xqc_memcpy(scid->cid_buf, pos, scid->cid_len);
    pos += scid->cid_len;

    /* check cid */
    if (xqc_cid_is_equal(&(packet->pkt_dcid), &c->dcid) != XQC_OK
        || xqc_cid_is_equal(&(packet->pkt_scid), &c->scid) != XQC_OK)
    {
        /* log & ignore packet */
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_long_header|invalid dcid or scid|");
        return XQC_ERROR;
    }

    if (xqc_packet_version_check(c, version) != XQC_OK) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_long_header|version check err|");
        return XQC_ERROR;
    }

    /* version negotiation */
    if (version == 0) {
        return xqc_packet_parse_version_negotiation(c, packet_in);
    }

    /* don't update packet_in->pos = pos here, need prefix inside*/
    /* long header common part finished */

    switch (type)
    {
        case XQC_PTYPE_INIT:
            ret = xqc_packet_parse_initial(c, packet_in);
            break;
        case XQC_PTYPE_0RTT:
            ret = xqc_packet_parse_zero_rtt(c, packet_in);
            break;
        case XQC_PTYPE_HSK:
            ret = xqc_packet_parse_handshake(c, packet_in);
            break;
        case XQC_PTYPE_RETRY:
            ret = xqc_packet_parse_retry(c, packet_in);
            break;
        default:
            xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_long_header|invalid packet type|%ui|", type);
            ret = XQC_ERROR;
            break;
    }

    if (ret == XQC_OK && c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
    }

    return ret;
}
