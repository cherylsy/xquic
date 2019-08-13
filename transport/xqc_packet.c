
#include <common/xqc_errno.h>
#include "include/xquic.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "common/xqc_algorithm.h"
#include "common/xqc_variable_len_int.h"
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


/**
 * @retval XQC_OK / XQC_ERROR
 */
xqc_int_t
xqc_packet_process_single(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;

    xqc_int_t ret = XQC_ERROR;

    if (XQC_PACKET_IN_LEFT_SIZE(packet_in) == 0) {
        return -XQC_ENOBUF;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {

        ret = xqc_packet_parse_short_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|xqc_packet_parse_short_header error|");
            return ret;
        }

        /* check handshake */
        if (!xqc_conn_check_handshake_completed(c)) {
            xqc_log(c->log, XQC_LOG_WARN,
                    "|buff 1RTT packet before handshake completed|");

            /* buffer packets */
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_1RTT);

            packet_in->pos = packet_in->last;
            return XQC_OK;
        }
    } else {  /* long header */

        if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_0RTT &&
                !xqc_tls_check_0rtt_key_ready(c)) {

            xqc_log(c->log, XQC_LOG_WARN, "|buff 0RTT before initial received|");
            /* buffer packets */
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_0RTT);

            packet_in->pos = packet_in->last;
            return XQC_OK;
        }
        else if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_HSK &&
                !xqc_tls_check_hs_rx_key_ready(c)) {

            xqc_log(c->log, XQC_LOG_WARN, "|buff HSK before hs_rx_key_ready|");
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_HSK);

            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        ret = xqc_packet_parse_long_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|xqc_packet_parse_long_header error|");
            return ret;
        }

        if (packet_in->pi_pkt.pkt_type == XQC_PTYPE_RETRY) {
            xqc_log(c->log, XQC_LOG_INFO, "|====>|pkt_type:%s|recv_time:%ui|",
                    xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pkt_recv_time);
            return XQC_OK;
        }
    }
    unsigned char *last = packet_in->last;

    /*packet_in->pos = packet_in->decode_payload;
    packet_in->last = packet_in->decode_payload + packet_in->decode_payload_len;*/

    //printf("recv crypto data :%d\n", packet_in->last - packet_in->pos);
    //hex_print(packet_in->pos, packet_in->last - packet_in->pos);
    ret = xqc_do_decrypt_pkt(c, packet_in);
    if (ret == XQC_OK) {
        ret = xqc_process_frames(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|xqc_process_frames error|");
            return ret;
        }
    } else {
        if (ret == XQC_EARLY_DATA_REJECT) {
            xqc_log(c->log, XQC_LOG_DEBUG, "|decrypt early data reject, continue |");
            packet_in->pos = packet_in->last;
            return XQC_OK;
        } else {
            xqc_log(c->log, XQC_LOG_ERROR, "|decrypt data error, return|");
            return ret;
        }
    }

    packet_in->last = last;

    xqc_log(c->log, XQC_LOG_INFO, "|====>|pkt_type:%s|pkt_num:%ui|frame:%s|recv_time:%ui|",
            xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num,
            xqc_frame_type_2_str(packet_in->pi_frame_types), packet_in->pkt_recv_time);

    xqc_pkt_range_status range_status;
    int out_of_order = 0;

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
            "|xqc_recv_record_add|status:%d|pkt_num:%ui|largest:%ui|pns:%d|",
            range_status, packet_in->pi_pkt.pkt_num,
            xqc_recv_record_largest(&c->recv_record[packet_in->pi_pkt.pkt_pns]), packet_in->pi_pkt.pkt_pns);

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
    /* QUIC包的起始地址 */
    const unsigned char *pos = packet_in_buf;
    /* UDP包的结束地址 */
    const unsigned char *end = packet_in_buf + packet_in_size;

    xqc_packet_in_t packet;
    unsigned char decrypt_payload[MAX_PACKET_LEN];

    printf("recv packet %d\n", packet_in_size);
    hex_print((char *)packet_in_buf, packet_in_size);

    while (pos < end) {

        last_pos = pos;

        xqc_packet_in_t *packet_in = &packet;
        memset(packet_in, 0, sizeof(*packet_in));
        xqc_packet_in_init(packet_in, pos, end - pos, decrypt_payload, MAX_PACKET_LEN, recv_time);

        /* packet_in->pos will update inside */
        ret = xqc_packet_process_single(c, packet_in);

        /* err in parse packet, don't cause dead loop */
        if (ret != XQC_OK || last_pos == packet_in->pos) {
            xqc_log(c->log, XQC_LOG_WARN, "|process packets err|ret:%z|pos:%p|buf:%p|buf_size:%z|",
                                          ret, packet_in->pos,
                                          packet_in->buf, packet_in->buf_size);
            return ret != XQC_OK ? ret : -XQC_ESYS;
        }

        //从上一个QUIC包的结束开始处理下一个包
        pos = packet_in->last;


    }

    return XQC_OK;
}




