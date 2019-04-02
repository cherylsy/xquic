
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_conn.h"



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
    unsigned char pos = packet_in->pos;
    xqc_packet_t *packet = &packet_in->pi_pkt;
    xqc_uint_t i;

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
        xqc_log(c->log, XQC_LOG_WARN, "parse short header: invalid destination cid")
        return XQC_ERROR;
    }
    
    /* packet number */
    packet->pkt_num = 0;
    for (i = 0; i < packet_number_len; i++) {
        packet->pkt_num = (packet->pkt_num << 8) + (*pos);
        pos++;
    }

    /* protected payload */


    return XQC_OK;
}

/* handshake finished */
xqc_int_t
xqc_packet_parse(xqc_connection_t *c,
                       xqc_packet_in_t *packet_in)
{
    unsigned char pos = packet_in->pos;

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) == 0) {
        return XQC_ERROR;
    }

    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {
        return xqc_packet_parse_short_header(c, packet_in);
    }

    /* normal case, ignore */
    xqc_log(c->log, XQC_LOG_DEBUG, "recvd long header packet after handshake finishd.")

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
xqc_conn_server_do_handshake(xqc_connection_t *c,
                                        xqc_packet_in_t *packet_in)
{

    return XQC_OK;
}


xqc_int_t
xqc_conn_client_do_handshake(xqc_connection_t *c,
                                        xqc_packet_in_t *packet_in)
{
    return XQC_OK;
}


/**
 * @retval size of parsed bytes
 */
xqc_int_t
xqc_conn_process_single_packet(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    if (xqc_conn_check_handshake_completed(c)) {
        ret = xqc_packet_parse(c, packet_in);    
    } else {
        if (c->conn_type == XQC_CONN_TYPE_SERVER) {
            ret = xqc_conn_server_do_handshake(c, packet_in);
        } else {
            ret = xqc_conn_client_do_handshake(c, packet_in);
        }
    }

    return ret;
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
        if (ret < 0 || last_pos == packet_in->pos) {
            xqc_log(c->log, XQC_LOG_WARN, "process packets err|%z|%p|%p|%z|", 
                                          res, (void *)packet_in->pos,
                                          (void *)packet_in->buf, packet_in->buf_size);
            return XQC_ERROR;
        }
    }

    return XQC_OK;
}


