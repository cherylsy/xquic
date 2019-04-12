
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_frame.h"

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;
    TAILQ_INIT(&send_ctl->ctl_packets);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_ctl->ctl_unacked_packets[pns]);
    }
    return send_ctl;
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;

    TAILQ_FOREACH_REVERSE(packet_out, &ctl->ctl_packets, xqc_packets_tailq, po_next) {
        if (packet_out->po_pkt.pkt_pns == pns &&
            packet_out->po_buf_size - packet_out->po_used_size >= need) {
            return packet_out;
        }
    }

    packet_out = xqc_create_packet_out(ctl->ctl_conn->conn_pool, ctl, pns);
    if (packet_out == NULL) {
        return NULL;
    }


    return packet_out;
}

int
xqc_send_ctl_can_send (xqc_connection_t *conn)
{
    //TODO: check if can send
    return 1;
}

void
xqc_remove_unacked(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

int
xqc_process_ack (xqc_send_ctl_t *ctl, xqc_ack_info_t *const ack_info, xqc_msec_t ack_recv_time)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    unsigned char estimate_rtt = 0;
    xqc_packet_number_t lagest_ack = ack_info->ranges[0].high;
    xqc_packet_number_t smallest_unack;
    xqc_pktno_range_t *range = &ack_info->ranges[ack_info->n_ranges - 1];
    xqc_pkt_num_space_t pns = ack_info->pns;

    if (lagest_ack > ctl->ctl_largest_sent) {
        return XQC_ERROR;
    }

    packet_out = xqc_list_entry(&ctl->ctl_unacked_packets[pns], xqc_packet_out_t, po_list);
    if (packet_out == NULL) {
        return XQC_OK;
    }

    smallest_unack = packet_out->po_pkt.pkt_num;

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_num > lagest_ack) {
            break;
        }
        while (packet_out->po_pkt.pkt_num > range->high && range != ack_info->ranges) {
            --range;
        }

        if (packet_out->po_pkt.pkt_num >= range->low) {
            if (packet_out->po_pkt.pkt_num > ctl->ctl_largest_acked) {
                ctl->ctl_largest_acked = packet_out->po_pkt.pkt_num;
                ctl->ctl_largest_acked_sent_time = packet_out->po_sent_time;
            }

            if (packet_out->po_largest_ack > ctl->ctl_largest_ack_both[pns]) {
                ctl->ctl_largest_ack_both[pns] = packet_out->po_largest_ack;
            }

            //remove from unacked list
            xqc_remove_unacked(pos);

            if (packet_out->po_pkt.pkt_num == lagest_ack) {
                estimate_rtt = 1;
            }

            //TODO: free packet_out
        }
    }

    if (estimate_rtt) {
        //TODO: 估算RTT
    }

    if (pns == XQC_PNS_01RTT) {
        xqc_recv_record_del(&ctl->ctl_conn->recv_record[XQC_PNS_01RTT], ctl->ctl_largest_ack_both[XQC_PNS_01RTT] + 1);
    }
    return XQC_OK;
}