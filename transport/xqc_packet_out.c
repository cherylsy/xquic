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
    packet_out = xqc_pcalloc(pool, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_buf = xqc_pnalloc(pool, XQC_PACKET_OUT_SIZE);//TODO: change to malloc
    if (!packet_out->po_buf) {
        return NULL;
    }

    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_pns = pns;

    //TODO calc packet number
    packet_out->po_pkt.pkt_num = 0;

    xqc_list_add_tail(&packet_out->po_list, &ctl->ctl_packets);

    return packet_out;
}

int
xqc_should_generate_ack(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
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
                return XQC_ERROR;
            }
            packet_out->po_used_size += rc;

            rc = xqc_write_ack_to_one_packet(conn, packet_out, pns);
            if (rc != XQC_OK) {
                return XQC_ERROR;
            }

        }
    }
    return XQC_OK;
}