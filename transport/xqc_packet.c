
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_conn.h"
#include "../common/xqc_variable_len_int.h"


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

    return XQC_OK;
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

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) < XQC_PACKET_INITIAL_MIN_LENGTH) {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|initial size too small|%z|",
                                      XQC_PACKET_IN_LEFT_SIZE(packet_in));
        return XQC_ERROR;
    }

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
        || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + payload_len + packet_number_len) 
    {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|payload length err|");
        return XQC_ERROR;
    }

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* decrypt payload */

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_initial|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;
    
    return XQC_OK;
}

xqc_int_t
xqc_packet_parse_handshake(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|handshake|");

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_HSK;


    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_handshake|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;

    return XQC_OK;
}

xqc_int_t
xqc_packet_parse_zero_rtt(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|0-RTT|");

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_0RTT;


    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_zero_rtt|success|packe_num=%ui|", packet->pkt_num);
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


/* TODO: add parse */
xqc_int_t
xqc_packet_parse_version_negotiation(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet parse|version negotiation|");

    packet_in->pi_pkt.pkt_type = XQC_PTYPE_VERSION_NEGOTIATION;
    

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
    xqc_uint_t version = xqc_parse_uint32(pos);
    pos += XQC_PACKET_VERSION_LENGTH;

    /* version negotiation */
    if (version == 0) {
        return xqc_packet_parse_version_negotiation(c, packet_in);
    }

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

    packet_in->pos = pos;
    /* long header common part finished */

    switch (type)
    {
    case XQC_PACKET_TYPE_INIT:
        ret = xqc_packet_parse_initial(c, packet_in);
        break;
    case XQC_PACKET_TYPE_0RTT:
        ret = xqc_packet_parse_zero_rtt(c, packet_in);
        break;
    case XQC_PACKET_TYPE_HANDSHAKE:
        ret = xqc_packet_parse_handshake(c, packet_in);
        break;
    case XQC_PACKET_TYPE_RETRY:
        ret = xqc_packet_parse_retry(c, packet_in);
        break;
    default:
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_long_header|invalid packet type|%ui|", type);
        ret = XQC_ERROR;
        break;
    }

    return ret;
}


/**
 * @retval XQC_OK / XQC_ERROR
 */
xqc_int_t
xqc_conn_process_single_packet(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_int_t ret = XQC_ERROR;

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) == 0) {
        return XQC_ERROR;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {

        /* check handshake */
        if (!xqc_conn_check_handshake_completed(c)) {
            /* TODO: buffer packets */
            xqc_log(c->log, XQC_LOG_DEBUG, "|process_single_packet|recvd short header packet before handshake completed|");
            return XQC_OK;
        }

        return xqc_packet_parse_short_header(c, packet_in);
    }

    /* long header */
    if (xqc_conn_check_handshake_completed(c)) {
        /* ignore */
        xqc_log(c->log, XQC_LOG_DEBUG, "|process_single_packet|recvd long header packet after handshake finishd|");
        return XQC_OK;
    }
    
    return xqc_packet_parse_long_header(c, packet_in);
}


/**
 * 1 UDP payload = n QUIC packets
 */
xqc_int_t
xqc_conn_process_packets(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    unsigned char *last_pos = NULL;

    while (packet_in->pos < packet_in->last) {

        last_pos = packet_in->pos;

        /* packet_in->pos will update inside */
        ret = xqc_conn_process_single_packet(c, packet_in);

        /* err in parse packet, don't cause dead loop */
        if (ret != XQC_OK || last_pos == packet_in->pos) {
            xqc_log(c->log, XQC_LOG_WARN, "process packets err|%z|%p|%p|%z|", 
                                          ret, packet_in->pos,
                                          packet_in->buf, packet_in->buf_size);
            return XQC_ERROR;
        }
    }

    return XQC_OK;
}


