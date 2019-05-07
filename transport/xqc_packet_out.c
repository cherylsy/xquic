#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_send_ctl.h"
#include "xqc_frame_parser.h"
#include "../common/xqc_timer.h"
#include "xqc_packet_parser.h"

#define XQC_PACKET_OUT_SIZE 1280    //TODO 先写死

xqc_packet_out_t *
xqc_create_packet_out (xqc_memory_pool_t *pool, xqc_send_ctl_t *ctl, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;

    /*优先复用已申请*/
    xqc_list_for_each_safe(pos, next, &ctl->ctl_free_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        memset(packet_out, 0, sizeof(xqc_packet_out_t));

        xqc_send_ctl_remove_free(pos, ctl);

        goto set_packet;
    }


    packet_out = xqc_calloc(1, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_buf = xqc_malloc(XQC_PACKET_OUT_SIZE);
    if (!packet_out->po_buf) {
        return NULL;
    }

set_packet:
    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_pns = pns;

    //TODO calc packet number
    packet_out->po_pkt.pkt_num = ctl->ctl_packet_number[pns]++;

    xqc_send_ctl_insert_send(&packet_out->po_list, &ctl->ctl_packets, ctl);

    return packet_out;
}

int
xqc_should_generate_ack(xqc_connection_t *conn)
{
    //xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_should_generate_ack|flag=%d|", conn->conn_flag);
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_should_generate_ack yes|flag=%d|", conn->conn_flag);
        return 1;
    }
    return 0;
}

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns)
{
    int size, has_gap;
    xqc_packet_number_t largest_ack;
    xqc_msec_t now = xqc_gettimeofday();


    size = xqc_gen_ack_frame(packet_out->po_buf + packet_out->po_used_size, packet_out->po_buf_size - packet_out->po_used_size,
                      now, conn->trans_param.ack_delay_exponent, conn->recv_record, &has_gap, &largest_ack);
    if (size < 0) {
        return XQC_ERROR;
    }

    packet_out->po_used_size += size;
    packet_out->po_largest_ack = largest_ack;

    packet_out->po_frame_types |= XQC_FRAME_BIT_ACK;

    conn->ack_eliciting_pkt[pns] = 0;
    if (has_gap) {
        conn->conn_flag |= XQC_CONN_FLAG_ACK_HAS_GAP;
    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_ACK_HAS_GAP;
    }
    conn->conn_flag &= ~(XQC_CONN_FLAG_SHOULD_ACK_INIT << pns);

    return XQC_OK;
}

int
 xqc_write_ack_to_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    //TODO calc packet_number_bits
    unsigned char packet_number_bits = 0;
    xqc_pkt_type_t pkt_type;

    int rc;

    for (pns = 0; pns < XQC_PNS_N; ++pns) {
        if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {
            packet_out = xqc_create_packet_out(conn->conn_pool, conn->conn_send_ctl, pns);
            if (packet_out == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets xqc_create_packet_out error");
                return XQC_ERROR;
            }

            if (pns == XQC_PNS_HSK) {
                pkt_type = XQC_PTYPE_HSK;
            } else if (pns == XQC_PNS_INIT) {
                pkt_type = XQC_PTYPE_INIT;
            } else {
                pkt_type = XQC_PTYPE_SHORT_HEADER;
            }

            if (pns == XQC_PNS_01RTT && packet_out->po_used_size == 0) {
                rc = xqc_gen_short_packet_header(packet_out->po_buf,
                                                 packet_out->po_buf_size - packet_out->po_used_size,
                                                 conn->dcid.cid_buf, conn->dcid.cid_len,
                                                 packet_number_bits, packet_out->po_pkt.pkt_num);
            } else if (pns != XQC_PNS_01RTT && packet_out->po_used_size == 0) {
                rc = xqc_gen_long_packet_header(packet_out,
                                                conn->dcid.cid_buf, conn->dcid.cid_len,
                                                conn->scid.cid_buf, conn->scid.cid_len,
                                                NULL, 0,
                                                XQC_QUIC_VERSION, pkt_type,
                                                packet_out->po_pkt.pkt_num, packet_number_bits);
            }
            if (rc < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets gen header error");
                return XQC_ERROR;
            }
            packet_out->po_used_size += rc;

            rc = xqc_write_ack_to_one_packet(conn, packet_out, pns);
            if (rc != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets xqc_write_ack_to_one_packet error");
                return XQC_ERROR;
            }

            xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_write_ack_to_packets pns=%d", pns);

        }
    }
    return XQC_OK;
}