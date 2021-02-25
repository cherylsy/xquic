
#include <xquic/xquic.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_algorithm.h"
#include "src/common/xqc_variable_len_int.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_engine.h"



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
            return XQC_PNS_APP_DATA;
        case XQC_PTYPE_HSK:
            return XQC_PNS_HSK;
        case XQC_PTYPE_SHORT_HEADER:
            return XQC_PNS_APP_DATA;
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

int
xqc_confirm_cid(xqc_connection_t *c, xqc_packet_t *pkt)
{
    /** 
     *  after a successful process of Initial packet, SCID from Initial
     *  is not equal to what remembered when connection was created, it
     *  might owing to:
     *  1) server is not willing to use the client's DCID as SCID;
     *  2) client's Initial packet is corrupted, pkt_scid is distorted; 
     */
    if (!(c->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
        if (!xqc_cid_is_equal(&c->dcid, &pkt->pkt_scid)) {
            xqc_cid_copy(&c->dcid, &pkt->pkt_scid);
        }

        /* if the original dcid remember by server might be corrypted, correct it */
        if (c->conn_type == XQC_CONN_TYPE_SERVER
            && !xqc_cid_is_equal(&c->ocid, &pkt->pkt_dcid))
        {
            xqc_cid_copy(&c->ocid, &pkt->pkt_dcid);
        }

        if (xqc_insert_conns_hash(c->engine->conns_hash_dcid, c, &c->dcid)) {
            xqc_log(c->log, XQC_LOG_ERROR, "|client insert conn hash error");
            return -XQC_EMALLOC;
        }

        c->conn_flag |= XQC_CONN_FLAG_DCID_OK;
    }

    return XQC_OK;
}

uint8_t
xqc_packet_need_decrypt(xqc_packet_t *pkt)
{
    /* packets don't need decryption */
    return xqc_has_packet_number(pkt);
}

xqc_int_t
xqc_packet_parse_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_int_t ret = XQC_ERROR;

    if (XQC_BUFF_LEFT_SIZE(pos, packet_in->last) == 0) {
        ret = -XQC_EILLPKT;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {
        ret = xqc_packet_parse_short_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|xqc_packet_parse_short_header error:%d|", ret);
            return ret;
        }

        /* check handshake */
        if (!xqc_conn_check_handshake_completed(c)) {
            /* handshake not completed, buffer packets */
            xqc_log(c->log, XQC_LOG_WARN,
                    "|delay|buff 1RTT packet before handshake completed|");
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_1RTT);
            return -XQC_EWAITING;
        }

    } else if (XQC_PACKET_IS_LONG_HEADER(pos)) {    /* long header */
        /* buffer packets if key is not ready */
        if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_0RTT) {
            c->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;

            if (!xqc_tls_check_0rtt_key_ready(c)) {
                /* buffer packets */
                xqc_log(c->log, XQC_LOG_INFO, "|delay|buff 0RTT before 0rtt_key_ready|");
                xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_0RTT);
                return -XQC_EWAITING;
            }

        } else if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_HSK
                   && !xqc_tls_check_hs_rx_key_ready(c))
        {
            /* buffer packets */
            xqc_log(c->log, XQC_LOG_INFO, "|delay|buff HSK before hs_rx_key_ready|");
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_HSK);
            return -XQC_EWAITING;
        }

        /* parse packet */
        ret = xqc_packet_parse_long_header(c, packet_in);
        if (XQC_OK != ret) {
            xqc_log(c->log, XQC_LOG_ERROR,
                "|xqc_packet_parse_long_header error:%d|", ret);
            return ret;
        }

    } else {
        xqc_log(c->log, XQC_LOG_INFO, "unknown packet type, first byte[%d], "
                "skip all buf, skip length: %d", pos[0], packet_in->last - packet_in->pos);
        // packet_in->pos = packet_in->last;
        return -XQC_EIGNORE;
    }

    return ret;
}

xqc_int_t
xqc_packet_decrypt_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_OK;
    unsigned char *last = packet_in->last;
    /* decrypt packet */
    ret = xqc_packet_decrypt(c, packet_in);
    if (ret == XQC_OK) {
        /* process frames */
        xqc_log(c->log, XQC_LOG_DEBUG, "|pkt_type:%s|pkt_num:%ui|",
                xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num);
        ret = xqc_process_frames(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|xqc_process_frames error|%d|", ret);
            return ret;
        }

    } else {
        packet_in->pos = packet_in->last;   /* if decrypt failure, drop all bytes */
        if (ret == -XQC_TLS_DATA_REJECT) {
            xqc_log(c->log, XQC_LOG_DEBUG, "|decrypt early data reject, continue|");
            ret = -XQC_EIGNORE;

        } else {
            xqc_log(c->log, XQC_LOG_WARN, "|decrypt data error, return|%d|pkt_type:%s|pkt_num:%ui|",
                    ret, xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num);
            ret = -XQC_EILLPKT;
        }
    }
    packet_in->last = last;
    return ret;
}

void
xqc_packet_record_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    xqc_pkt_range_status range_status;
    int out_of_order = 0;
    xqc_pkt_num_space_t pns = packet_in->pi_pkt.pkt_pns;
    xqc_packet_number_t pkt_num = packet_in->pi_pkt.pkt_num;

    range_status = xqc_recv_record_add(&c->recv_record[pns], pkt_num,
                                       packet_in->pkt_recv_time);
    if (range_status == XQC_PKTRANGE_OK) {
        if (XQC_IS_ACK_ELICITING(packet_in->pi_frame_types)) {
            ++c->ack_eliciting_pkt[pns];
        }
        if (pkt_num > c->conn_send_ctl->ctl_largest_recvd[pns]) {
            c->conn_send_ctl->ctl_largest_recvd[pns] = pkt_num;
        }
        if (pkt_num != xqc_recv_record_largest(&c->recv_record[pns])) {
            out_of_order = 1;
        }
        xqc_maybe_should_ack(c, pns, out_of_order, packet_in->pkt_recv_time);
    }

    xqc_recv_record_log(c, &c->recv_record[pns]);
    xqc_log(c->log, XQC_LOG_DEBUG, "|xqc_recv_record_add|status:%d|pkt_num:%ui|largest:%ui|pns:%d|",
            range_status, pkt_num, xqc_recv_record_largest(&c->recv_record[pns]), pns);
}

xqc_int_t
xqc_packet_process_single(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    /* parse packet */
    ret = xqc_packet_parse_single(c, packet_in);
    if (XQC_OK != ret) {
        return ret;
    }

    /* those packets with no packet number, don't need to be decrypt or put into CC */
    if (!xqc_packet_need_decrypt(&packet_in->pi_pkt)) {
        return ret;
    }

    /* decrypt packet */
    ret = xqc_packet_decrypt_single(c, packet_in);
    if (ret == XQC_OK) {
        /* sucessful decryption of Initial/Handshake packet is important to quic conn state */
        if (packet_in->pi_pkt.pkt_type == XQC_PTYPE_INIT) {
            xqc_confirm_cid(c, &packet_in->pi_pkt);
        }

        xqc_log(c->log, XQC_LOG_DEBUG, "|packet process suc|type:%s|frames:%s|pkt_num:%d|",
            xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), 
            xqc_frame_type_2_str(packet_in->pi_frame_types),
            packet_in->pi_pkt.pkt_num);

    } else {
        return ret;
    }

    /* record packet */
    xqc_packet_record_single(c, packet_in);

    /* 需要立即跑main_logic */
    if (packet_in->pi_frame_types & (~(XQC_FRAME_BIT_STREAM|XQC_FRAME_BIT_PADDING))) {
        c->conn_flag |= XQC_CONN_FLAG_NEED_RUN;
    }
    return XQC_OK;
}


/**
 * 1 UDP payload = n QUIC packets
 */
xqc_int_t
xqc_packet_process(xqc_connection_t *c,
                   const unsigned char *packet_in_buf,
                   size_t packet_in_size,
                   xqc_msec_t recv_time)
{
    xqc_int_t ret = XQC_ERROR;
    const unsigned char *last_pos = NULL;
    const unsigned char *pos = packet_in_buf;                   /* start of QUIC pkt */
    const unsigned char *end = packet_in_buf + packet_in_size;  /* end of udp datagram */
    xqc_packet_in_t packet;
    unsigned char decrypt_payload[MAX_PACKET_LEN];

    /* process all QUIC packets in UDP datagram */
    while (pos < end) {
        last_pos = pos;

        /* init packet in */
        xqc_packet_in_t *packet_in = &packet;
        memset(packet_in, 0, sizeof(*packet_in));
        xqc_packet_in_init(packet_in, pos, end - pos, decrypt_payload, MAX_PACKET_LEN, recv_time);

        /* packet_in->pos will update inside */
        ret = xqc_packet_process_single(c, packet_in);
        if (XQC_OK == ret) {
            xqc_log(c->log, XQC_LOG_INFO, "|====>|conn:%p|size:%uz|pkt_type:%s|pkt_num:%ui|frame:%s|recv_time:%ui|",
                    c, packet_in->buf_size,
                    xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num,
                    xqc_frame_type_2_str(packet_in->pi_frame_types), packet_in->pkt_recv_time);

        } else if (-XQC_EVERSION == ret || -XQC_EILLPKT == ret || -XQC_EWAITING == ret || -XQC_EIGNORE == ret) {
            /* error tolerance situations */
            ret = XQC_OK;

        } else if (ret != XQC_OK || last_pos == packet_in->pos) {
            /* err in parse packet, don't cause dead loop */
            xqc_log(c->log, XQC_LOG_ERROR, "|process packets err|ret:%d|pos:%p|buf:%p|buf_size:%uz|",
                    ret, packet_in->pos, packet_in->buf, packet_in->buf_size);
            return ret != XQC_OK ? ret : -XQC_ESYS;
        }

        /* consume all the bytes and start parse next QUIC packet */
        pos = packet_in->last;
    }

    return XQC_OK;
}


/* check if the packet has packet number */
uint8_t
xqc_has_packet_number(xqc_packet_t *pkt)
{
    /* VERSION_NEGOTIATION/RETRY packet don't have packet number */
    if (XQC_UNLIKELY(XQC_PTYPE_VERSION_NEGOTIATION == pkt->pkt_type
                     || XQC_PTYPE_RETRY == pkt->pkt_type))
    {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

