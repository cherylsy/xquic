
#include <common/xqc_errno.h>
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
    [XQC_PTYPE_SHORT_HEADER] = "SHORT_HEADER",
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

xqc_pkt_num_space_t
xqc_packet_type_to_pns(xqc_pkt_type_t pkt_type)
{
    switch (pkt_type) {
        case XQC_PTYPE_INIT:
            return XQC_PNS_INIT;
        case XQC_PTYPE_0RTT:
            return XQC_PNS_01RTT;
        case XQC_PTYPE_HSK:
            return XQC_PNS_HSK;
        case XQC_PTYPE_SHORT_HEADER:
            return XQC_PNS_01RTT;
        default:
            return XQC_PNS_N;
    }
}

xqc_pkt_type_t
xqc_state_to_pkt_type(xqc_connection_t *conn)
{
    switch (conn->conn_state) {
        case XQC_CONN_STATE_CLIENT_INIT:
        case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
        case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
        case XQC_CONN_STATE_SERVER_INIT:
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
        case XQC_CONN_STATE_SERVER_INITIAL_SENT:
            return XQC_PTYPE_INIT;
        case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
        case XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT:
        case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
        case XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD:
            return XQC_PTYPE_HSK;
        default:
            return XQC_PTYPE_SHORT_HEADER;
    }
}

/*
 * 发送版本协商协议
 * */
static inline xqc_int_t
xqc_packet_send_version_negotiation(xqc_connection_t *c)
{
    xqc_packet_out_t *packet_out = xqc_create_packet_out(c->conn_send_ctl, XQC_PTYPE_VERSION_NEGOTIATION);
    if (packet_out == NULL) {
        return -XQC_ENULLPTR;
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
            return -XQC_EPROTO;
        }

        /*版本号不匹配*/
        if (c->version != version) {
            return -XQC_EPROTO;
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
        return -XQC_ENOBUF;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {

        /* check handshake */
        if (!xqc_conn_check_handshake_completed(c)) {
            /* TODO: buffer packets */
            xqc_log(c->log, XQC_LOG_WARN,
                    "|process_single_packet|recvd short header packet before handshake completed|");
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        ret = xqc_packet_parse_short_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|process_single_packet|xqc_packet_parse_short_header error|");
            return ret;
        }
    } else {  /* long header */

        if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_0RTT
                && c->conn_type == XQC_CONN_TYPE_SERVER
                && c->conn_state < XQC_CONN_STATE_SERVER_INITIAL_RECVD) {
            xqc_log(c->log, XQC_LOG_ERROR, "|ignore 0RTT before initial received|");
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        /* TODO: 0RTT回退 用于模拟0rtt失败 */
#if 0
        if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_0RTT
            && c->conn_type == XQC_CONN_TYPE_SERVER) {
            xqc_log(c->log, XQC_LOG_ERROR, "|ignore 0RTT test|");
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }
#endif

        ret = xqc_packet_parse_long_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|process_single_packet|xqc_packet_parse_long_header error|");
            return ret;
        }
    }
    unsigned char *last = packet_in->last;

    /*packet_in->pos = packet_in->decode_payload;
    packet_in->last = packet_in->decode_payload + packet_in->decode_payload_len;*/

    ret = xqc_do_decrypt_pkt(c, packet_in);
    if(ret == 0){
        ret = xqc_process_frames(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|process_single_packet|xqc_process_frames error|");
            return ret;
        }
    }else{
        if(ret ==  XQC_EARLY_DATA_REJECT){
            xqc_log(c->log, XQC_LOG_DEBUG, "|process_single_packet|decrypt early data reject, continue |");
            packet_in->pos = packet_in->last;
        }else{
            xqc_log(c->log, XQC_LOG_ERROR, "|process_single_packet|decrypt data error, return|");
            return ret;
        }
    }

    packet_in->last = last;

    xqc_log(c->log, XQC_LOG_INFO, "====>|xqc_conn_process_single_packet|pkt_type=%s|pkt_num=%ui|frame=%s|recv_time=%ui|",
            xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num,
            xqc_frame_type_2_str(packet_in->pi_frame_types), packet_in->pkt_recv_time);

    xqc_pkt_range_status range_status;
    int out_of_order = 0;

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
    xqc_log(c->log, XQC_LOG_DEBUG,
            "|xqc_conn_process_single_packet|xqc_recv_record_add|status=%d|pkt_num=%ui|largest=%ui|pns=%d|",
            range_status, packet_in->pi_pkt.pkt_num,
            xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns]), packet_in->pi_pkt.pkt_pns);

    return XQC_OK;
}


/**
 * 1 UDP payload = n QUIC packets
 */
xqc_int_t
xqc_conn_process_packets(xqc_connection_t *c,
                         const unsigned char *packet_in_buf,
                         size_t packet_in_size,
                         xqc_msec_t recv_time)
{
    xqc_int_t ret = XQC_ERROR;
    const unsigned char *last_pos = NULL;
    /* QUIC包的起始地址 */
    const unsigned char *pos = packet_in_buf;
    /* UDP包的结束地址 */
    const unsigned char *end = packet_in_buf + packet_in_size;

    c->conn_send_ctl->ctl_bytes_recv += packet_in_size;

    xqc_packet_in_t packet;
    unsigned char decrypt_payload[MAX_PACKET_LEN];

    //printf("recv packet %d\n", packet_in_size);
    hex_print((char *)packet_in_buf, packet_in_size);

    while (pos < end) {

        last_pos = pos;

        xqc_packet_in_t *packet_in = &packet;
        memset(packet_in, 0, sizeof(*packet_in));
        xqc_init_packet_in(packet_in, pos, end - pos, decrypt_payload, MAX_PACKET_LEN, recv_time);

        /* packet_in->pos will update inside */
        ret = xqc_conn_process_single_packet(c, packet_in);

        /* err in parse packet, don't cause dead loop */
        if (ret != XQC_OK || last_pos == packet_in->pos) {
            xqc_log(c->log, XQC_LOG_WARN, "process packets err|%z|%p|%p|%z|",
                                          ret, packet_in->pos,
                                          packet_in->buf, packet_in->buf_size);
            return ret != XQC_OK ? ret : -XQC_ESYS;
        }

        //从上一个QUIC包的结束开始处理下一个包
        pos = packet_in->last;


    }

    return XQC_OK;
}




