#include <string.h>
#include <openssl/hmac.h>
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_variable_len_int.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/xqc_algorithm.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/http3/xqc_h3_conn.h"

#define xqc_packet_number_bits2len(b) ((b) + 1)

#define XQC_RESET_TOKEN_LEN 16

static const unsigned char xqc_proto_version_field[XQC_VERSION_MAX][XQC_PROTO_VERSION_LEN] = {

    [XQC_IDRAFT_INIT_VER] = { 0, 0, 0, 1 },
    [XQC_IDRAFT_VER_27] = { 0xFF, 0, 0, 27, },
    [XQC_IDRAFT_VER_28] = { 0xFF, 0, 0, 28, },
    [XQC_IDRAFT_VER_29] = { 0xFF, 0, 0, 29, },
    [XQC_IDRAFT_VER_NEGOTIATION] = { 0x00, 0x00, 0x00, 0x00, },
};



unsigned
xqc_short_packet_header_size (unsigned char dcid_len, unsigned char pktno_bits)
{
    return 1 //first byte
           + dcid_len
           + xqc_packet_number_bits2len(pktno_bits);
}

unsigned
xqc_long_packet_header_size (unsigned char dcid_len, unsigned char scid_len, unsigned token_len,
                             unsigned char pktno_bits, xqc_pkt_type_t type)
{
    return 1 //first byte
           + 4 //version
           + 2 //DCID Len (8) SCID Len (8)
           + dcid_len
           + scid_len
           + (type == XQC_PTYPE_INIT ? xqc_vint_len_by_val((unsigned)token_len) + token_len : 0)
           + XQC_LONG_HEADER_LENGTH_BYTE //Length (i)
           + xqc_packet_number_bits2len(pktno_bits);
}


xqc_int_t
xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                     unsigned char *buf, size_t size)
{
    unsigned char *pos = NULL;
    const unsigned char *end = buf + size;

    if (size <= 0) {
        return -XQC_EPARAM;
    }

    if ((buf[0] & 0x40) == 0) {
        return -XQC_EILLPKT;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(buf)) {
        if (size < 1 + cid_len) {
            return -XQC_EILLPKT;
        }

        xqc_cid_set(dcid, buf + 1, cid_len);
        return XQC_OK;
    }

    /* long header */
    if (size < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH + 2) {
        return -XQC_EILLPKT;
    }

    pos = buf + 1 + XQC_PACKET_VERSION_LENGTH;
    dcid->cid_len = (uint8_t)(*pos);
    if (dcid->cid_len > XQC_MAX_CID_LEN) {
        return -XQC_EILLPKT;
    }
    pos += 1;

    if (XQC_BUFF_LEFT_SIZE(pos, end) < dcid->cid_len + 1) {
        return -XQC_EILLPKT;
    }
    xqc_memcpy(dcid->cid_buf, pos, dcid->cid_len);
    pos += dcid->cid_len;

    scid->cid_len = (uint8_t)(*pos);
    if(scid->cid_len > XQC_MAX_CID_LEN) {
        return -XQC_EILLPKT;
    }
    pos += 1;

    if (XQC_BUFF_LEFT_SIZE(pos, end) < scid->cid_len) {
        return -XQC_EILLPKT;
    }
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
        *packet_num = ((*packet_num) << 8u) + (*pos);
        pos++;
    }
}

/**
 * https://tools.ietf.org/html/draft-ietf-quic-transport-24#page-80
 * @param largest_pn Largest received packet number
 * @param truncated_pn Packet number parsed from header
 * @param pn_nbits Number of bits the truncated_pn has
 * @return
 */
xqc_packet_number_t
xqc_decode_packet_num(xqc_packet_number_t largest_pn, xqc_packet_number_t truncated_pn, unsigned pn_nbits)
{
    xqc_packet_number_t expected_pn, pn_win, pn_hwin, pn_mask, candidate_pn;
    expected_pn = largest_pn + 1;
    pn_win = (xqc_packet_number_t) 1 << pn_nbits;
    pn_hwin = pn_win >> (xqc_packet_number_t) 1;
    pn_mask = pn_win - 1;
    // The incoming packet number should be greater than
    // expected_pn - pn_hwin and less than or equal to
    // expected_pn + pn_hwin
    //
    // This means we can't just strip the trailing bits from
    // expected_pn and add the truncated_pn because that might
    // yield a value outside the window.
    //
    // The following code calculates a candidate value and
    // makes sure it's within the packet number window.
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    if (candidate_pn + pn_hwin <= expected_pn) {
        return candidate_pn + pn_win;
    }
    // Note the extra check for underflow when candidate_pn
    // is near zero.
    if (candidate_pn > expected_pn + pn_hwin &&
        candidate_pn > pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

int
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
        return -XQC_ENOBUF;
    }

    dst_buf[0] = 0x40 | spin_bit << 5 | reserved_bits << 3 | key_phase_bit << 2 | packet_number_bits;
    dst_buf++;

    if (dcid_len) {
        memcpy(dst_buf, dcid, dcid_len);
    }
    dst_buf += dcid_len;

    packet_out->po_ppktno = dst_buf;

    dst_buf += xqc_write_packet_number(dst_buf, packet_number, packet_number_bits);//packet_number update when send
    packet_out->po_payload = dst_buf;

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
    uint8_t cid_len = c->engine->config->cid_len;

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_APP_DATA;

    if (XQC_BUFF_LEFT_SIZE(pos, packet_in->last) < 1 + cid_len) {
        return -XQC_ENOBUF;
    }

    /* check fixed bit(0x40) = 1 */
    if ((pos[0] & 0x40) == 0) {
        xqc_log(c->log, XQC_LOG_ERROR, "|parse short header: fixed bit err|");
        return -XQC_EILLPKT;
    }

    xqc_uint_t spin_bit = (pos[0] & 0x20) >> 5;
    xqc_uint_t reserved_bits = (pos[0] & 0x18) >> 3;
    xqc_uint_t key_phase = (pos[0] & 0x04) >> 2;
    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;
    pos += 1;

    xqc_log(c->log, XQC_LOG_DEBUG, "|parse short header|spin_bit:%ud|reserved_bits:%ud|key_phase:%ud|packet_number_len:%ud|",
            spin_bit, reserved_bits,
            key_phase, packet_number_len);

    /* check dcid */
    xqc_cid_set(&(packet->pkt_dcid), pos, cid_len);
    pos += cid_len;
    if (xqc_cid_is_equal(&(packet->pkt_dcid), &c->scid) != XQC_OK) {
        /* log & ignore */
        xqc_log(c->log, XQC_LOG_ERROR, "|parse short header|invalid destination cid|");
        return -XQC_EILLPKT;
    }

    /* packet number */
    packet_in->pi_pkt.length = packet_in->last - pos;
    packet_in->pi_pkt.pkt_num_offset = pos - packet_in->buf;

    /* protected payload */


    if (c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
    }


    return XQC_OK;
}


void
xqc_long_packet_update_length (xqc_packet_out_t *packet_out)
{
    if (packet_out->po_pkt.pkt_type == XQC_PTYPE_INIT
        || packet_out->po_pkt.pkt_type == XQC_PTYPE_HSK
        || packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT)
    {
        unsigned char *plength = packet_out->po_ppktno - XQC_LONG_HEADER_LENGTH_BYTE;
        unsigned length = packet_out->po_buf + packet_out->po_used_size - packet_out->po_ppktno;
        xqc_vint_write(plength, length, 0x01, 2);
    }
}

void
xqc_short_packet_update_dcid(xqc_packet_out_t *packet_out, xqc_connection_t *conn)
{
    unsigned char *dst = packet_out->po_buf + 1;
    //dcid len不能变
    xqc_memcpy(dst, conn->dcid.cid_buf, conn->dcid.cid_len);
}

int
xqc_gen_long_packet_header (xqc_packet_out_t *packet_out,
                            const unsigned char *dcid, unsigned char dcid_len,
                            const unsigned char *scid, unsigned char scid_len,
                            const unsigned char *token, unsigned token_len,
                            xqc_proto_version_t ver,
                            unsigned char pktno_bits)
{
    unsigned char *dst_buf = packet_out->po_buf;
    size_t dst_buf_size = packet_out->po_buf_size - packet_out->po_used_size;

    xqc_pkt_type_t type = packet_out->po_pkt.pkt_type;
    xqc_packet_number_t packet_number = packet_out->po_pkt.pkt_num;

    unsigned int need = xqc_long_packet_header_size(dcid_len, scid_len, token_len, pktno_bits, type);

    unsigned char *begin = dst_buf;
    unsigned char bits;
    unsigned int vlen;

    if (!xqc_check_proto_version_valid(ver)) {
        return -XQC_EPROTO;
    }

    if (need > dst_buf_size) {
        return -XQC_ENOBUF;
    }

    if (dcid_len < 3 || scid_len < 3) {
        return -XQC_EILLPKT;
    }

    unsigned char first_byte = 0xC0;
    first_byte |= type << 4;
    first_byte |= pktno_bits;
    *dst_buf++ = first_byte;

    memcpy(dst_buf, xqc_proto_version_field[ver], XQC_PROTO_VERSION_LEN);
    dst_buf += XQC_PROTO_VERSION_LEN;

    *dst_buf = dcid_len;
    dst_buf++;
    memcpy(dst_buf, dcid, dcid_len);
    dst_buf += dcid_len;

    *dst_buf = scid_len;
    dst_buf++;
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

    dst_buf += XQC_LONG_HEADER_LENGTH_BYTE; //Length update when write frame

    packet_out->po_ppktno = dst_buf;
    dst_buf += xqc_write_packet_number(dst_buf, packet_number, pktno_bits); //packet_number update when send
    packet_out->po_payload = dst_buf;

    return dst_buf - begin;

}


/*
+-+-+-+-+-+-+-+-+
|1|1| 0 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
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
    unsigned char *end = packet_in->last;
    int size = 0;
    uint64_t token_len = 0, length = 0;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|initial|");

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_INIT;

    if (c->conn_state == XQC_CONN_STATE_SERVER_INIT &&
        !(c->conn_flag & XQC_CONN_FLAG_SVR_INIT_RECVD)) {
        if (XQC_BUFF_LEFT_SIZE(packet_in->buf, end) < XQC_PACKET_INITIAL_MIN_LENGTH) {
            xqc_log(c->log, XQC_LOG_ERROR, "|initial size too small|%z|",
                    XQC_BUFF_LEFT_SIZE(packet_in->buf, end));
            XQC_CONN_ERR(c, TRA_PROTOCOL_VIOLATION);
            return -XQC_EILLPKT;
        }
        c->conn_flag |= XQC_CONN_FLAG_SVR_INIT_RECVD;
    }

    /* Token Length(i) & Token */
    size = xqc_vint_read(pos, end, &token_len);
    if (size < 0 || XQC_BUFF_LEFT_SIZE(pos, end) < size + token_len) {
        xqc_log(c->log, XQC_LOG_ERROR, "|token length err|%ui|", token_len);
        return -XQC_EVINTREAD;
    }
    pos += size;

    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(c->log, XQC_LOG_ERROR, "|token length exceed XQC_MAX_TOKEN_LEN|%ui|", token_len);
        return -XQC_ELIMIT;
    }

    /* 服务端保存token，解crypto frame时校验token */
    if (c->conn_type == XQC_CONN_TYPE_SERVER) {
        memcpy(c->conn_token, pos, token_len);
        c->conn_token_len = token_len;
    }
    pos += token_len;

    /* Length(i) */
    size = xqc_vint_read(pos, end, &length);
    if (size < 0
        || XQC_BUFF_LEFT_SIZE(pos, end) < size + length)
    {
        xqc_log(c->log, XQC_LOG_ERROR, "|length err|%ui|", length);
        return -XQC_EILLPKT;
    }
    pos += size;

    if (XQC_BUFF_LEFT_SIZE(pos, end) < length) {
        xqc_log(c->log, XQC_LOG_ERROR, "|last offset error|");
        return -XQC_EILLPKT;
    }

    packet_in->last = pos + length;
    packet_in->pi_pkt.length = length;
    packet_in->pi_pkt.pkt_num_offset = pos - packet_in->buf;

    /* packet number */
    /* decrypt payload */
    /* process in xqc_packet_decrypt */

    xqc_log(c->log, XQC_LOG_DEBUG, "|success|Length:%ui|", length);

    return XQC_OK;
}


/*
+-+-+-+-+-+-+-+-+
|1|1| 1 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
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
    unsigned char *end = packet_in->last;
    ssize_t size = 0;
    uint64_t length = 0;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|0-RTT|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_0RTT;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_APP_DATA;

    //TODO: 0RTT丢包重传会触发错误
    /*if ((++c->zero_rtt_count) > XQC_PACKET_0RTT_MAX_COUNT) {
        xqc_log(c->log, XQC_LOG_ERROR, "|packet_parse_zero_rtt|too many 0-RTT packets|%ud|", c->zero_rtt_count);
        return -XQC_EPROTO;
    }*/

    /* Length(i) */
    size = xqc_vint_read(pos, packet_in->last, &length);
    if (size < 0
        || XQC_BUFF_LEFT_SIZE(pos, end) < size + length)
    {
        xqc_log(c->log, XQC_LOG_ERROR, "|length err|%ui|", length);
        return -XQC_EILLPKT;
    }
    pos += size;

    packet_in->last = pos + length;
    packet_in->pi_pkt.length = length;
    packet_in->pi_pkt.pkt_num_offset = pos - packet_in->buf;

    xqc_log(c->log, XQC_LOG_DEBUG, "|success|Length:%ui|", length);

    return XQC_OK;
}

int xqc_packet_encrypt_buf(xqc_connection_t *conn, xqc_packet_out_t *packet_out, unsigned char *enc_pkt, size_t *enc_pkt_len)
{
    xqc_pktns_t *p_pktns;
    xqc_encrypt_t encrypt_func;
    xqc_hp_mask_t hp_mask;

    xqc_crypto_km_t *p_ckm = NULL;
    xqc_vec_t *tx_hp = NULL;

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_out->po_pkt.pkt_type);

    xqc_tls_context_t *p_ctx = &conn->tlsref.crypto_ctx_store[encrypt_level];

    if (encrypt_level == XQC_ENC_LEV_INIT) {
        p_pktns = &conn->tlsref.initial_pktns;
        p_ckm = &p_pktns->tx_ckm;
        tx_hp = &p_pktns->tx_hp;
        encrypt_func = conn->tlsref.callbacks.in_encrypt;
        hp_mask = conn->tlsref.callbacks.in_hp_mask;
        p_ctx  = &conn->tlsref.hs_crypto_ctx;
    } else if (encrypt_level == XQC_ENC_LEV_0RTT) {
        p_ckm = &conn->tlsref.early_ckm;
        tx_hp = &conn->tlsref.early_hp;
        encrypt_func = conn->tlsref.callbacks.encrypt;
        hp_mask = conn->tlsref.callbacks.hp_mask;
    } else if (encrypt_level == XQC_ENC_LEV_HSK) {
        p_pktns = &conn->tlsref.hs_pktns;
        p_ckm = &p_pktns->tx_ckm;
        tx_hp = &p_pktns->tx_hp;
        encrypt_func = conn->tlsref.callbacks.encrypt;
        hp_mask = conn->tlsref.callbacks.hp_mask;
    } else if (encrypt_level == XQC_ENC_LEV_1RTT) {
        p_pktns = &conn->tlsref.pktns;
        p_ckm = &p_pktns->tx_ckm;
        tx_hp = &p_pktns->tx_hp;
        encrypt_func = conn->tlsref.callbacks.encrypt;
        hp_mask = conn->tlsref.callbacks.hp_mask;
    } else {
        return -XQC_EILLPKT;
    }

    unsigned char nonce[XQC_NONCE_LEN];
    xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, packet_out->po_pkt.pkt_num);

    unsigned char *pkt_hd = packet_out->po_buf;
    unsigned int hdlen = (packet_out->po_payload - packet_out->po_buf);
    unsigned int payloadlen = packet_out->po_used_size - hdlen;
    unsigned char *payload = packet_out->po_payload;
    int pktno_len = (packet_out->po_buf[0] & XQC_PKT_NUMLEN_MASK) + 1;

    memcpy(enc_pkt, pkt_hd, hdlen);/* copy header to buf */

    /* refresh header length */
    if (encrypt_level == XQC_ENC_LEV_INIT || encrypt_level == XQC_ENC_LEV_0RTT ||
        encrypt_level == XQC_ENC_LEV_HSK) {
        unsigned char *plength = enc_pkt + (packet_out->po_ppktno - XQC_LONG_HEADER_LENGTH_BYTE - packet_out->po_buf);
        uint32_t length = packet_out->po_buf + packet_out->po_used_size - packet_out->po_ppktno ;
        length += xqc_aead_overhead(&p_ctx->aead,length);
        xqc_vint_write(plength, length, 0x01, 2);
    }

    ssize_t nwrite = encrypt_func(conn, enc_pkt + hdlen, *(enc_pkt_len) - hdlen, payload, payloadlen,
                              p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, enc_pkt, hdlen, (void*)encrypt_level);

    if (nwrite < 0 || nwrite != (payloadlen + xqc_aead_overhead(&p_ctx->aead,payloadlen))) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|%z|", nwrite);
        return -XQC_EENCRYPT;
    }

    *enc_pkt_len = nwrite + hdlen;

    unsigned char mask[XQC_HP_SAMPLELEN];
    unsigned char *po_ppktno = enc_pkt + (packet_out->po_ppktno - packet_out->po_buf);

    nwrite = hp_mask(conn, mask, sizeof(mask), tx_hp->base, tx_hp->len, po_ppktno + 4, XQC_HP_SAMPLELEN, (void*)encrypt_level);

    if (nwrite < XQC_HP_MASKLEN) {
        return -XQC_EENCRYPT;
    }

    xqc_pkt_type_t pkt_type = packet_out->po_pkt.pkt_type;
    unsigned char *p = enc_pkt;
    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        *p = (unsigned char) (*p ^ (mask[0] & 0x1f));
    } else {
        *p = (unsigned char) (*p ^ (mask[0] & 0x0f));
    }

    p = po_ppktno;
    int i = 0;
    for (i = 0; i < pktno_len; ++i) {
        *(p + i) ^= mask[i + 1];
    }
    return XQC_OK;
}

int xqc_packet_encrypt(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    conn->enc_pkt_len = sizeof(conn->enc_pkt);
    return xqc_packet_encrypt_buf(conn, packet_out, conn->enc_pkt, &conn->enc_pkt_len);
}


int 
xqc_packet_decrypt(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_pkt_type_t pkt_type = packet_in->pi_pkt.pkt_type;
    xqc_pkt_num_space_t pns = packet_in->pi_pkt.pkt_pns;

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(pkt_type);
    xqc_pktns_t *p_pktns = NULL;
    xqc_encrypt_t decrypt_func = NULL;
    xqc_hp_mask_t hp_mask = NULL;

    xqc_crypto_km_t *ckm = NULL;
    xqc_vec_t *hp = NULL;

    if (XQC_ENC_LEV_0RTT == encrypt_level) {
        if(xqc_crypto_is_early_data_accepted(conn) == XQC_FALSE) {

            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_packet_decrypt|early data not decrypt");
            return -XQC_TLS_DATA_REJECT;
        }
    }

    switch (encrypt_level) {

        case XQC_ENC_LEV_INIT:
            p_pktns = &conn->tlsref.initial_pktns;
            ckm = &p_pktns->rx_ckm;
            hp = &p_pktns->rx_hp;
            decrypt_func = conn->tlsref.callbacks.in_decrypt;
            hp_mask = conn->tlsref.callbacks.in_hp_mask;
            break;

        case XQC_ENC_LEV_0RTT:
            ckm = &conn->tlsref.early_ckm;
            hp = &conn->tlsref.early_hp;
            decrypt_func = conn->tlsref.callbacks.decrypt;
            hp_mask = conn->tlsref.callbacks.hp_mask;
            break;

        case XQC_ENC_LEV_HSK:
            p_pktns = &conn->tlsref.hs_pktns;
            ckm = &p_pktns->rx_ckm;
            hp = &p_pktns->rx_hp;
            hp_mask = conn->tlsref.callbacks.hp_mask;
            decrypt_func = conn->tlsref.callbacks.decrypt;
            break;
        case XQC_ENC_LEV_1RTT:
            p_pktns = &conn->tlsref.pktns;
            ckm = &p_pktns->rx_ckm;
            hp = &p_pktns->rx_hp;
            hp_mask = conn->tlsref.callbacks.hp_mask;
            decrypt_func = conn->tlsref.callbacks.decrypt;
            break;
        default:
            xqc_log(conn->log, XQC_LOG_ERROR, "|do_decrypt_pkt|invalid packet type|%ud|", pkt_type);
            return -XQC_EILLPKT;

    }

    if (ckm->key.base == NULL || ckm->key.len == 0 
        || ckm->iv.base == NULL || ckm->iv.len == 0 
        || hp->base == NULL || hp->len == 0) 
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|do_decrypt_pkt|decrypt key NULL|");

        return -XQC_EDECRYPT;
    }

    unsigned char *pkt = (unsigned char*)packet_in->buf;
    size_t pkt_num_offset = packet_in->pi_pkt.pkt_num_offset;
    size_t sample_offset = pkt_num_offset + 4;
    char mask[XQC_HP_SAMPLELEN];
    char header_decrypt[1500];
    size_t header_len = 0;

    char *p = header_decrypt;
    memcpy(p, pkt, pkt_num_offset);
    p = p + pkt_num_offset;

    int nwrite = (int)hp_mask(conn, mask, sizeof(mask), hp->base, hp->len, pkt + sample_offset, XQC_HP_SAMPLELEN, (void*)encrypt_level);
    if (nwrite < XQC_HP_MASKLEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|do_decrypt_pkt|hp_mask return error:%d|", nwrite);
        return nwrite;
    }

    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        header_decrypt[0] = (uint8_t) (header_decrypt[0] ^ (mask[0] & 0x1f));
    } else {
        header_decrypt[0] = (uint8_t) (header_decrypt[0] ^ (mask[0] & 0x0f));
    }


    xqc_uint_t packet_number_len = (header_decrypt[0] & 0x03) + 1;

    for (unsigned i = 0; i < packet_number_len; ++i) {
        *p++ = *(pkt + pkt_num_offset + i) ^ mask[i + 1];
    }

    header_len = pkt_num_offset + packet_number_len;

    xqc_packet_parse_packet_number(header_decrypt + pkt_num_offset, packet_number_len, &packet_in->pi_pkt.pkt_num);

#ifdef STANDARD_NONCE
    /* 标准nonce，先解码出pkt_num，然后将pkt_num作为参数构建nonce */
    packet_in->pi_pkt.pkt_num = xqc_decode_packet_num(conn->conn_send_ctl->ctl_largest_recvd[pns],
                                                      packet_in->pi_pkt.pkt_num, packet_number_len * 8);

    uint8_t nonce[XQC_NONCE_LEN];
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, packet_in->pi_pkt.pkt_num);
#else
    /* 兼容线上老版本NONCE生成方式：先create nonce，在decode packet_num */
    uint8_t nonce[64];
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, packet_in->pi_pkt.pkt_num);

    packet_in->pi_pkt.pkt_num = xqc_decode_packet_num(conn->conn_send_ctl->ctl_largest_recvd[pns],
                                                      packet_in->pi_pkt.pkt_num, packet_number_len * 8);
#endif

    char *decrypt_buf = (char *) (packet_in->decode_payload);
    unsigned char *payload = pkt + pkt_num_offset + packet_number_len;
    size_t payload_len = packet_in->pi_pkt.length - packet_number_len;
    nwrite = (int)decrypt_func(conn, decrypt_buf, packet_in->decode_payload_size, payload, payload_len, ckm->key.base,
                          ckm->key.len, nonce, ckm->iv.len, header_decrypt, header_len, (void*) encrypt_level);

    if (nwrite < 0 || nwrite > payload_len) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|do_decrypt_pkt|decrypt_func return error:%d|", nwrite);
        return nwrite;
    }

    packet_in->decode_payload_len = nwrite;
    memcpy(payload, decrypt_buf, nwrite);

    packet_in->pos = payload;

    packet_in->last = payload + nwrite;


    return XQC_OK;
}


/*
+-+-+-+-+-+-+-+-+
|1|1| 2 |R R|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
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
    unsigned char *end = packet_in->last;
    int size = 0;
    uint64_t length = 0;

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_HSK;
    packet_in->pi_pkt.pkt_pns = XQC_PNS_HSK;

    /* Length(i) */
    size = xqc_vint_read(pos, end, &length);
    if (size < 0
        || XQC_BUFF_LEFT_SIZE(pos, end) < size + length)
    {
        xqc_log(c->log, XQC_LOG_ERROR, "|length err|");
        return -XQC_EILLPKT;
    }
    pos += size;

    packet_in->last = pos + length;

    /* packet number */
    packet_in->pi_pkt.length = length;
    packet_in->pi_pkt.pkt_num_offset = pos - packet_in->buf;

    xqc_log(c->log, XQC_LOG_DEBUG, "|success|Length:%ui|", length);

    return XQC_OK;
}

/*
 *
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1| 3 | Unused|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Retry Token (*)                      ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                   Retry Integrity Tag (128)                   +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       Retry Packet
 */
//TODO: retry 协议更新
int
xqc_gen_retry_packet(unsigned char *dst_buf,
                     const unsigned char *dcid, unsigned char dcid_len,
                     const unsigned char *scid, unsigned char scid_len,
                     const unsigned char *odcid, unsigned char odcid_len,
                     const unsigned char *token, unsigned token_len,
                     unsigned ver)
{

    unsigned char *begin = dst_buf;

    unsigned char first_byte = 0xC0;
    first_byte |= XQC_PTYPE_RETRY << 4;
    first_byte |= odcid_len - 3;
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
    memcpy(dst_buf, odcid, odcid_len);
    dst_buf += odcid_len;

    memcpy(dst_buf, token, token_len);
    dst_buf += token_len;

    return dst_buf - begin;
}

xqc_int_t
xqc_packet_parse_retry(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|retry|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_RETRY;

    if (++c->retry_count > 1) {
        packet_in->pos = packet_in->last;
        xqc_log(c->log, XQC_LOG_DEBUG, "|retry_count exceed 1 return|");
        return XQC_OK;
    }

    if (c->conn_type != XQC_CONN_TYPE_CLIENT) {
        return -XQC_EPROTO;
    }

    xqc_cid_t odcid;
    odcid.cid_len = (*pos & 0x0F) + 3;

    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
           + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;

    xqc_memcpy(odcid.cid_buf, pos, odcid.cid_len);
    pos += odcid.cid_len;

    //判断odcid
    if (c->ocid.cid_len != odcid.cid_len
           || memcmp(c->ocid.cid_buf, odcid.cid_buf, odcid.cid_len) != 0) {
        xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_retry|ocid not match|");
        packet_in->pos = packet_in->last;
        return XQC_OK;
    }

    xqc_memcpy(c->conn_token, pos, packet_in->last - pos);
    c->conn_token_len = packet_in->last - pos;

    /*printf("xqc_packet_parse_retry token:\n");
    hex_print(c->conn_token,c->conn_token_len);*/

    //存储token
    c->engine->eng_callback.save_token(xqc_conn_get_user_data(c), c->conn_token, c->conn_token_len);

    /* 重新发起握手 */
    c->conn_state = XQC_CONN_STATE_CLIENT_INIT;
    //xqc_destroy_stream(c->crypto_stream[XQC_ENC_LEV_INIT]);
    c->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(c, XQC_ENC_LEV_INIT, NULL);

    if (c->tlsref.callbacks.recv_retry(c, &c->dcid) < 0) {
        return -XQC_TLS_CLIENT_REINTIAL_ERROR;
    }

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_retry|success|");
    packet_in->pos = packet_in->last;

    return XQC_OK;
}


#if (XQC_VERSION_NEGOTIATION)
/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|  Unused (7) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Version (32)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..2040)           ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..2040)              ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Supported Version 1 (32)                 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   [Supported Version 2 (32)]                ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   [Supported Version N (32)]                ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                  Version Negotiation Packet
*/

/* TODO: 版本协商未使用 */
xqc_int_t
xqc_packet_parse_version_negotiation(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    unsigned char *end = packet_in->last;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|version negotiation|");
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_VERSION_NEGOTIATION;

    /*至少需要一个support version*/
    if (XQC_BUFF_LEFT_SIZE(pos, end) < XQC_PACKET_VERSION_LENGTH) {
        xqc_log(c->log, XQC_LOG_DEBUG, "|version negotiation size too small|%z|", XQC_BUFF_LEFT_SIZE(pos, end));
        return -XQC_EILLPKT;
    }

    /*检查dcid & scid已经在外层函数完成*/

    /*check available states*/
    if (c->conn_state != XQC_CONN_STATE_CLIENT_INITIAL_SENT) {
        /* drop packet */
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|invalid state|%i|", (int)c->conn_state);
        return -XQC_ESTATE;
    }

    /*check conn type*/
    if (c->conn_type != XQC_CONN_TYPE_CLIENT) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|invalid conn_type|%i|", (int)c->conn_type);
        return -XQC_EPROTO;
    }

    /*check discard vn flag*/
    if (c->discard_vn_flag != 0) {
        packet_in->pos = packet_in->last;
        return XQC_OK;
    }

    /*get Supported Version list*/
    uint32_t supported_version_list[256];
    uint32_t supported_version_count = 0;

    while (XQC_BUFF_LEFT_SIZE(pos, end) >= XQC_PACKET_VERSION_LENGTH) {
        uint32_t version = *(uint32_t*)pos;
        if (version) {
            if (xqc_uint32_list_find(supported_version_list, supported_version_count, version) == -1) {
                if (supported_version_count < sizeof(supported_version_list) / sizeof(*supported_version_list)) {
                    supported_version_list[supported_version_count++] = version;
                }
            } else { /*重复版本号*/
                xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_version_negotiation|dup version|%i|", version);
            }
        }
        pos += XQC_PACKET_VERSION_LENGTH;
    }

    packet_in->pos = packet_in->last;

    /*客户端当前使用版本跟support version list中的版本一样，忽略该VN包*/
    if (xqc_uint32_list_find(supported_version_list, supported_version_count, c->version) != -1) {
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
        return -XQC_ESYS;
    }

    /*设置客户端版本*/
    c->version = version_chosen;

    /*TODO:zuo 用新的版本号重新连接服务器*/
    xqc_stream_t *stream = c->crypto_stream[XQC_ENC_LEV_INIT];
    if (stream == NULL) {
        return -XQC_ESTREAM_NFOUND;
    }
    xqc_stream_ready_to_write(stream);

    /*设置discard vn flag*/
    c->discard_vn_flag = 1;

    return XQC_OK;
}

#endif /* XQC_VERSION_NEGOTIATION */


/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     Long Header Packet Format
*/

xqc_int_t
xqc_packet_parse_long_header(xqc_connection_t *c,
                             xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    unsigned char *end = packet_in->last;
    xqc_packet_t  *packet = &packet_in->pi_pkt;
    xqc_int_t ret = XQC_ERROR;

    if (XQC_BUFF_LEFT_SIZE(pos, end) < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH + 2) {
        return -XQC_EILLPKT;
    }

    /* check fixed bit(0x40) = 1 */
    if ((pos[0] & 0x40) == 0) {
        xqc_log(c->log, XQC_LOG_ERROR, "|fixed bit err|");
        return -XQC_EILLPKT;
    }

    xqc_uint_t type = (pos[0] & 0x30) >> 4;
    pos++;

    /* TODO: version check */
    uint32_t version = xqc_parse_uint32(pos);
    pos += XQC_PACKET_VERSION_LENGTH;

    /* get dcid & scid */
    xqc_cid_t *dcid = &packet->pkt_dcid;
    xqc_cid_t *scid = &packet->pkt_scid;
    dcid->cid_len = (uint8_t)(*pos);
    pos += 1;
    if (XQC_BUFF_LEFT_SIZE(pos, end) < dcid->cid_len + 1) {
        return -XQC_EILLPKT;
    }
    xqc_memcpy(dcid->cid_buf, pos, dcid->cid_len);
    pos += dcid->cid_len;

    scid->cid_len = (uint8_t)(*pos);
    pos += 1;

    if (XQC_BUFF_LEFT_SIZE(pos, end) < scid->cid_len) {
        return -XQC_EILLPKT;
    }
    xqc_memcpy(scid->cid_buf, pos, scid->cid_len);
    pos += scid->cid_len;

    //update pos
    packet_in->pos = pos;

    if (!(c->conn_flag & XQC_CONN_FLAG_DCID_OK) && c->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_cid_copy(&c->dcid, &packet->pkt_scid);
        if (xqc_insert_conns_hash(c->engine->conns_hash_dcid, c, &c->dcid)) {
            return -XQC_EMALLOC;
        }
        c->conn_flag |= XQC_CONN_FLAG_DCID_OK;
    } else if (type != XQC_PTYPE_INIT && type != XQC_PTYPE_0RTT) {

        /* check cid */
        if (xqc_cid_is_equal(&(packet->pkt_dcid), &c->scid) != XQC_OK
            || xqc_cid_is_equal(&(packet->pkt_scid), &c->dcid) != XQC_OK) {
            /* log & ignore packet */
            xqc_log(c->log, XQC_LOG_ERROR, "|invalid dcid or scid|");
            return -XQC_EILLPKT;
        }
    }

    if (xqc_conn_version_check(c, version) != XQC_OK) {
        xqc_log(c->log, XQC_LOG_WARN, "|version check err|");
        return -XQC_EILLPKT;
    }

    /* version negotiation */
    /*if (version == 0) {
        return xqc_packet_parse_version_negotiation(c, packet_in);
    }*/

    /* don't update packet_in->pos = pos here, need prefix inside*/
    /* long header common part finished */

    switch (type)
    {
        case XQC_PTYPE_INIT:
            if((c->conn_type == XQC_CONN_TYPE_SERVER) && (c->conn_state == XQC_CONN_STATE_SERVER_INIT) && ((c->tlsref.flags & XQC_CONN_FLAG_RETRY_SENT) == 0) ){
                ret = c->tlsref.callbacks.recv_client_initial(c, dcid, NULL); //
                if(ret < 0){
                    return ret;
                }
            }
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
            xqc_log(c->log, XQC_LOG_ERROR, "|invalid packet type|%ui|", type);
            ret = -XQC_EILLPKT;
            break;
    }

    if (ret == XQC_OK && c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
    }

    return ret;
}


void
xqc_gen_reset_token(xqc_cid_t *cid, unsigned char *token, int token_len)
{
    // HMAC or HKDF with static key
    //memcpy(token, cid->cid_buf, cid->cid_len);
    char key[] = ".@34dshj+={}";
    unsigned char *input = cid->cid_buf;
    int input_len = cid->cid_len;
    unsigned char output[EVP_MAX_MD_SIZE];
    int output_len = EVP_MAX_MD_SIZE;
    const EVP_MD * engine = NULL;
    engine = EVP_md5();
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, key, strlen(key), engine, NULL);
    HMAC_Update(ctx, input, input_len);

    HMAC_Final(ctx, output, &output_len);
    HMAC_CTX_free(ctx);

    memcpy(token, output, output_len < token_len ? output_len : token_len);
}

/*
 *     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|1|               Unpredictable Bits (182..)                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                   Stateless Reset Token (128)                 +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 6: Stateless Reset Packet
 */
xqc_int_t
xqc_gen_reset_packet(xqc_cid_t *cid, unsigned char *dst_buf)
{
    const unsigned char *begin = dst_buf;
    const int unpredictable_len = 23;
    int padding_len;
    unsigned char token[XQC_RESET_TOKEN_LEN] = {0};

    dst_buf[0] = 0x40;
    dst_buf++;

    if (cid->cid_len > 0) {
        memcpy(dst_buf, cid->cid_buf, cid->cid_len);
        dst_buf += cid->cid_len;
    } else {
        return -XQC_EILLPKT;
    }

    padding_len = unpredictable_len - (dst_buf - begin);
    if (padding_len < 0) {
        return -XQC_EILLPKT;
    }

    memset(dst_buf, 0, padding_len);
    dst_buf += padding_len;

    xqc_gen_reset_token(cid, token, XQC_RESET_TOKEN_LEN);
    memcpy(dst_buf, token, sizeof(token));
    dst_buf += sizeof(token);

    return dst_buf - begin;
}

int
xqc_is_reset_packet(xqc_cid_t *cid, const unsigned char *buf, unsigned buf_size)
{
    if (XQC_PACKET_IS_LONG_HEADER(buf)) {
        return 0;
    }

    if (buf_size < 39) {
        return 0;
    }

    const unsigned char *token;
    token = buf + (buf_size - XQC_RESET_TOKEN_LEN);

    unsigned char calc_token[XQC_RESET_TOKEN_LEN] = {0};
    xqc_gen_reset_token(cid, calc_token, XQC_RESET_TOKEN_LEN);

    if (memcmp(token,calc_token, XQC_RESET_TOKEN_LEN) == 0) {
        return 1;
    }
    return 0;
}
