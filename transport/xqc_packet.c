
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_algorithm.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_send_ctl.h"
#include "xqc_recv_record.h"
#include "xqc_packet_parser.h"

static const char * const pkt_type_2_str[XQC_PTYPE_NUM] = {
    [XQC_PTYPE_INIT]  = "INIT",
    [XQC_PTYPE_0RTT]  = "0RTT",
    [XQC_PTYPE_HSK]   = "HSK",
    [XQC_PTYPE_RETRY] = "RETRY",
    [XQC_PTYPE_SHORT_HEADER] = "SHORT_HEARER",
    [XQC_PTYPE_VERSION_NEGOTIATION] = "VERSION_NEGOTIATION",
};

const char *
xqc_pkt_type_2_str(xqc_pkt_type_t pkt_type)
{
    return pkt_type_2_str[pkt_type];
}

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
xqc_int_t
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
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        ret = xqc_packet_parse_short_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|process_single_packet|xqc_packet_parse_short_header error|");
            return ret;
        }
    } else {  /* long header */

        ret = xqc_packet_parse_long_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|process_single_packet|xqc_packet_parse_long_header error|");
            return ret;
        }
    }

    ret = xqc_process_frames(c, packet_in);
    if (ret != XQC_OK) {
        xqc_log(c->log, XQC_LOG_ERROR, "|process_single_packet|xqc_process_frames error|");
        return ret;
    }

    return XQC_OK;
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

        xqc_log(c->log, XQC_LOG_INFO, "====>|xqc_conn_process_packets|pkt_type=%s|pkt_num=%ui|frame=%s|",
                xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num,
                xqc_frame_type_2_str(packet_in->pi_frame_types));

        //TODO: 放在包解析前，判断是否是重复的包XQC_PKTRANGE_DUP，如果接收过则不需要重复解包
        range_status = xqc_recv_record_add(&c->recv_record[packet_in->pi_pkt.pkt_pns], packet_in->pi_pkt.pkt_num,
                            packet_in->pkt_recv_time);
        if (range_status == XQC_PKTRANGE_OK) {
            if (XQC_IS_ACK_ELICITING(packet_in->pi_frame_types)) {
                ++c->ack_eliciting_pkt[packet_in->pi_pkt.pkt_pns];
            }
            if (packet_in->pi_pkt.pkt_num != xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns])) {
                out_of_order = 1;
            }
            xqc_maybe_should_ack(c, packet_in->pi_pkt.pkt_pns, out_of_order, packet_in->pkt_recv_time);
        }

        xqc_recv_record_log(c, &c->recv_record[packet_in->pi_pkt.pkt_pns]);
        xqc_log(c->log, XQC_LOG_DEBUG, "|xqc_conn_process_packets|xqc_recv_record_add|status=%d|pkt_num=%ui|largest=%ui|",
                range_status, packet_in->pi_pkt.pkt_num, xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns]));
    }

    return XQC_OK;
}




