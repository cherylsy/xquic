
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_algorithm.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_send_ctl.h"

xqc_encrypt_level_t
xqc_packet_type_to_enc_level(xqc_pkt_type_t pkt_type)
{
    switch (pkt_type) {
        case XQC_PTYPE_INIT:
            return XQC_ENC_LEV_INIT;
        case XQC_PTYPE_0RTT:
            return XQC_ENC_LEV_0RTT;
        case XQC_PTYPE_HSK:
            return XQC_ENC_LEV_HSK;
        case XQC_PTYPE_SHORT_HEADER:
            return XQC_ENC_LEV_1RTT;
        default:
            return XQC_ENC_LEV_INIT;
    }
}

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

    if (c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
    }

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

    /* check available states */
    if (c->conn_state != XQC_CONN_STATE_SERVER_INIT
        && c->conn_state != XQC_CONN_STATE_CLIENT_INITIAL_SENT
        && c->conn_state != XQC_CONN_STATE_CLIENT_INITIAL_RECVD)
    {
        /* drop packet */
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_initial|invalid state|%i|",
                                      c->conn_state);
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
    pos += payload_len - packet_number_len;

    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_initial|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;

    /* finish parse & update conn state */
    if (c->conn_state == XQC_CONN_STATE_SERVER_INIT) {
        c->conn_state = XQC_CONN_STATE_SERVER_INITIAL_RECVD;
    }

    if (c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT) {
        c->conn_state = XQC_CONN_STATE_CLIENT_INITIAL_RECVD;
    }

    /* insert Initial & Handshake into packet send queue */

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet->pkt_type);
    xqc_stream_t *stream = c->crypto_stream[encrypt_level];
    if (stream) {
        xqc_stream_ready_to_read(stream);
    } else {
        xqc_create_crypto_stream(c, NULL);
    }
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


    xqc_uint_t packet_number_len = (pos[0] & 0x03) + 1;

    pos += XQC_PACKET_LONG_HEADER_PREFIX_LENGTH 
           + packet->pkt_dcid.cid_len + packet->pkt_scid.cid_len;
    packet_in->pos = pos;
    
    /* Length(i) */
    size = xqc_vint_read(pos, packet_in->last, &payload_len);
    if (size < 0 
        || XQC_PACKET_IN_LEFT_SIZE(packet_in) < size + payload_len + packet_number_len) 
    {
        xqc_log(c->log, XQC_LOG_WARN, "|packet_parse_handshake|payload length err|");
        return XQC_ERROR;
    }

    /* packet number */
    xqc_packet_parse_packet_number(pos, packet_number_len, &packet->pkt_num);
    pos += packet_number_len;

    /* decrypt payload */
    pos += payload_len - packet_number_len;


    xqc_log(c->log, XQC_LOG_DEBUG, "|packet_parse_handshake|success|packe_num=%ui|", packet->pkt_num);
    packet_in->pos = pos;

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet->pkt_type);
    xqc_stream_t *stream = c->crypto_stream[encrypt_level];
    if (stream) {
        xqc_stream_ready_to_read(stream);
    } else {
        xqc_create_crypto_stream(c, NULL);
    }

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
 * 发送版本协商协议
 * */
static inline xqc_int_t
xqc_packet_send_version_negotiation(xqc_connection_t *c)
{
    xqc_packet_out_t *packet_out = xqc_create_packet_out(c->conn_pool, c->conn_send_ctl, 0);
    if (packet_out == NULL) {
        return XQC_ERROR;
    }
    //assert(packet_out->po_buf_size >= 1 + 4 + 1 + c->scid.cid_len + c->dcid.cid_len + 4);

    unsigned char* p = packet_out->po_buf;
    /*first byte*/
    *p++ = (1 << 7);

    /*version*/
    *(uint32_t*)p = 0;
    p += sizeof(uint32_t);
    
    /*DCIL(4)|SCIL(4)*/
    *p = (c->scid.cid_len - 3) << 4;
    *p |= c->dcid.cid_len - 3;
    ++p;

    /*dcid*/
    memcpy(p, c->scid.cid_buf, c->scid.cid_len);
    p += c->scid.cid_len;

    /*scid*/
    memcpy(p, c->dcid.cid_buf, c->dcid.cid_len);
    p += c->dcid.cid_len;

    /*supported version list*/
    uint32_t* version_list = c->engine->config->support_version_list;
    uint32_t version_count = c->engine->config->support_version_count;

    unsigned char* end = packet_out->po_buf + packet_out->po_buf_size;

    for (size_t i = 0; i < version_count; ++i) {
        if (p + sizeof(uint32_t) <= end) {
            *(uint32_t*)p = version_list[i];
            p += sizeof(uint32_t);
        } else {
            break;
        }
    }

    /*填充0*/
    memset(p, 0, end - p);

    /*设置used size*/
    packet_out->po_used_size = packet_out->po_buf_size;

    /*push to conns queue*/
    if (!(c->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(c->engine->conns_pq, c, c->last_ticked_time)) {
            c->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    return XQC_OK;
}

/*
 * 版本检查
 * */
static inline xqc_int_t
xqc_packet_version_check(xqc_connection_t *c, uint32_t version)
{
    xqc_engine_t* engine = c->engine;
    if (engine->eng_type == XQC_ENGINE_SERVER) {
        uint32_t *list = engine->config->support_version_list;
        uint32_t count = engine->config->support_version_count;
        if (xqc_uint32_list_find(list, count, version) == -1) {
            xqc_packet_send_version_negotiation(c); /*发送version negotiation*/
            return XQC_ERROR;
        }

        /*版本号不匹配*/
        if (c->version != version) {
            return XQC_ERROR;
        }
    }

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

    if (ret == XQC_OK && c->conn_type == XQC_CONN_TYPE_CLIENT) {
        c->discard_vn_flag = 1;
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
    xqc_pkt_range_status range_status;
    int out_of_order = 0;

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

        //TODO: 放在包解析前，判断是否是重复的包XQC_PKTRANGE_DUP，如果接收过则不需要重复解包
        range_status = xqc_recv_record_add(&c->recv_record[packet_in->pi_pkt.pkt_pns], packet_in->pi_pkt.pkt_num,
                            packet_in->pkt_recv_time);
        if (range_status == XQC_PKTRANGE_OK) {
            ++c->ack_eliciting_pkt[packet_in->pi_pkt.pkt_pns]; //TODO: ack padding不加计数
            if (packet_in->pi_pkt.pkt_num != xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns])) {
                out_of_order = 1;
            }
            xqc_maybe_should_ack(c, packet_in->pi_pkt.pkt_pns, out_of_order, packet_in->pkt_recv_time);
        }
        xqc_log(c->log, XQC_LOG_DEBUG, "|xqc_recv_record_add|status=%d|pkt_num=%ui|largest=%ui|",
                range_status, packet_in->pi_pkt.pkt_num, xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns]));
    }

    return XQC_OK;
}


static int
xqc_pktno_range_can_merge (xqc_pktno_range_node_t *node, xqc_packet_number_t packet_number)
{
    if (node->pktno_range.low - 1 == packet_number) {
        --node->pktno_range.low;
        return 1;
    }
    if (node->pktno_range.high + 1 == packet_number) {
        ++node->pktno_range.high;
        return 1;
    }
    return 0;
}

/**
 * insert into range list when receive a new packet
 */
xqc_pkt_range_status
xqc_recv_record_add (xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number, xqc_msec_t recv_time)
{
    xqc_list_head_t *pos, *prev;
    xqc_pktno_range_node_t *pnode, *prev_node;
    xqc_pktno_range_t range;
    pnode = prev_node = NULL;
    pos = prev = NULL;

    xqc_pktno_range_node_t *first = xqc_list_entry(&recv_record->list_head, xqc_pktno_range_node_t, list);
    if (first && packet_number > first->pktno_range.high) {
        recv_record->largest_pkt_recv_time = recv_time;
    }

    xqc_list_for_each(pos, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        if (packet_number <= pnode->pktno_range.high) {
            if (packet_number >= pnode->pktno_range.low) {
                return XQC_PKTRANGE_DUP;
            }
        } else {
            break;
        }
        prev = pos;
    }

    if (pos) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
    }
    if (prev) {
        prev_node = xqc_list_entry(prev, xqc_pktno_range_node_t, list);
    }

    if ((prev && xqc_pktno_range_can_merge(prev_node, packet_number)) ||
        (pnode && xqc_pktno_range_can_merge(pnode, packet_number))) {
        if (prev_node && pnode && (prev_node->pktno_range.low - 1 == pnode->pktno_range.high)) {
            prev_node->pktno_range.low = pnode->pktno_range.low;
            xqc_list_del_init(pos);
            xqc_free(pnode);
        }
    } else {
        xqc_pktno_range_node_t *new_node = xqc_calloc(1, sizeof(*new_node));
        if (!new_node)
            return XQC_PKTRANGE_ERR;
        new_node->pktno_range.low = new_node->pktno_range.high = packet_number;
        if (pos) {
            //insert before pos
            xqc_list_add_tail(&(new_node->list), pos);
        } else {
            //insert tail of the list
            xqc_list_add_tail(&(new_node->list), &recv_record->list_head);
        }
    }

    return XQC_PKTRANGE_OK;
}

/**
 * del packet number range < del_from
 */
void
xqc_recv_record_del (xqc_recv_record_t *recv_record, xqc_packet_number_t del_from)
{
    if (del_from < recv_record->rr_del_from) {
        return;
    }

    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_pktno_range_t *range;

    recv_record->rr_del_from = del_from;

    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        range = &pnode->pktno_range;

        if (range->low < del_from) {
            if (range->high < del_from) {
                xqc_list_del_init(pos);
                xqc_free(pnode);
            } else {
                range->low = del_from;
            }
        }
    }
}

xqc_packet_number_t
xqc_recv_record_largest(xqc_recv_record_t *recv_record)
{
    xqc_pktno_range_node_t *pnode = xqc_list_entry(recv_record->list_head.next, xqc_pktno_range_node_t, list);
    if (pnode) {
        return pnode->pktno_range.high;
    } else {
        return 0;
    }
}

void
xqc_maybe_should_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns, int out_of_order, xqc_msec_t now)
{
    /* Generating Acknowledgements

   QUIC SHOULD delay sending acknowledgements in response to packets,
   but MUST NOT excessively delay acknowledgements of ack-eliciting
   packets.  Specifically, implementations MUST attempt to enforce a
   maximum ack delay to avoid causing the peer spurious timeouts.  The
   maximum ack delay is communicated in the "max_ack_delay" transport
   parameter and the default value is 25ms.

   An acknowledgement SHOULD be sent immediately upon receipt of a
   second ack-eliciting packet.  QUIC recovery algorithms do not assume
   the peer sends an ACK immediately when receiving a second ack-
   eliciting packet.

   In order to accelerate loss recovery and reduce timeouts, the
   receiver SHOULD send an immediate ACK after it receives an out-of-
   order packet.  It could send immediate ACKs for in-order packets for
   a period of time that SHOULD NOT exceed 1/8 RTT unless more out-of-
   order packets arrive.  If every packet arrives out-of- order, then an
   immediate ACK SHOULD be sent for every received packet.

   Similarly, packets marked with the ECN Congestion Experienced (CE)
   codepoint in the IP header SHOULD be acknowledged immediately, to
   reduce the peer's response time to congestion events.

   As an optimization, a receiver MAY process multiple packets before
   sending any ACK frames in response.  In this case the receiver can
   determine whether an immediate or delayed acknowledgement should be
   generated after processing incoming packets.
    */
    if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {
        return;
    }

    if (conn->ack_eliciting_pkt[pns] >= 2 || out_of_order) {

        conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;
        xqc_send_ctl_timer_unset(conn->conn_send_ctl, XQC_TIMER_ACK_INIT << pns);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_maybe_should_ack|out_of_order=%d|ack_eliciting_pkt=%d|",
                out_of_order, conn->ack_eliciting_pkt[pns]);
    } else if (conn->ack_eliciting_pkt[pns] > 0) {
        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_ACK_INIT << pns,
                               now + conn->trans_param.max_ack_delay);
    }
}

