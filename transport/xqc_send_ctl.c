
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_frame.h"
#include "xqc_conn.h"

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;
    send_ctl->ctl_minrtt = 0xffffffff;

    xqc_init_list_head(&send_ctl->ctl_packets);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_ctl->ctl_unacked_packets[pns]);
    }

    xqc_send_ctl_timer_init(send_ctl);
    return send_ctl;
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;

    xqc_list_head_t *pos;

    xqc_list_for_each_reverse(pos, &ctl->ctl_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
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
xqc_send_ctl_remove_unacked(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_unacked(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_remove_send(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_send(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}


int
xqc_process_ack (xqc_send_ctl_t *ctl, xqc_ack_info_t *const ack_info, xqc_msec_t ack_recv_time)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    unsigned char update_rtt = 0;
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
            xqc_send_ctl_remove_unacked(pos);

            if (packet_out->po_pkt.pkt_num == lagest_ack &&
                packet_out->po_pkt.pkt_num == ctl->ctl_largest_acked &&
                XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                update_rtt = 1;
            }

            //TODO: free packet_out
        }
    }

    if (update_rtt) {
        xqc_send_ctl_update_rtt(ctl, ack_recv_time - ctl->ctl_largest_acked_sent_time, ack_info->ack_delay);
    }

    if (pns == XQC_PNS_01RTT) {
        xqc_recv_record_del(&ctl->ctl_conn->recv_record[XQC_PNS_01RTT], ctl->ctl_largest_ack_both[XQC_PNS_01RTT] + 1);
    }
    return XQC_OK;
}

/* timer callbacks */
void xqc_send_ctl_ack_expired(xqc_send_ctl_timer_type type, void *ctx)
{
    xqc_connection_t *conn = ((xqc_send_ctl_t*)ctx)->ctl_conn;
    xqc_pkt_num_space_t pns = type - XQC_TIMER_ACK_INIT;
    conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;
}

/* timer callbacks end */


void
xqc_send_ctl_timer_init(xqc_send_ctl_t *ctl)
{
    memset(ctl->ctl_timer, 0, XQC_TIMER_N * sizeof(xqc_send_ctl_timer_t));
    xqc_send_ctl_timer_t *timer;
    for (xqc_send_ctl_timer_type type = 0; type < XQC_TIMER_N; ++type) {
        timer = &ctl->ctl_timer[type];
        if (type == XQC_TIMER_ACK_INIT || type == XQC_TIMER_ACK_HSK || type == XQC_TIMER_ACK_01RTT) {
            timer->ctl_timer_callback = xqc_send_ctl_ack_expired;
            timer->ctl_ctx = ctl;
        }
    }
}

void
xqc_send_ctl_timer_expire(xqc_send_ctl_t *ctl, xqc_msec_t now)
{
    xqc_send_ctl_timer_t *timer;
    for (xqc_send_ctl_timer_type type = 0; type < XQC_TIMER_N; ++type) {
        timer = &ctl->ctl_timer[type];
        if (timer->ctl_timer_is_set && timer->ctl_expire_time < now) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                    "|xqc_send_ctl_timer_expire|type=%d|", type);
            timer->ctl_timer_callback(type, timer->ctl_ctx);
            xqc_send_ctl_timer_unset(ctl, type);
        }
    }
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.6
 */
void
xqc_send_ctl_update_rtt(xqc_send_ctl_t *ctl, xqc_msec_t latest_rtt, xqc_msec_t ack_delay)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|before update rtt|srtt=%ui, rttvar=%ui, minrtt=%ui, latest_rtt=%ui, ack_delay=%ui",
            ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, latest_rtt, ack_delay);
    // min_rtt ignores ack delay.
    ctl->ctl_minrtt = latest_rtt < ctl->ctl_minrtt ? latest_rtt : ctl->ctl_minrtt;
    // Limit ack_delay by max_ack_delay
    ack_delay = ack_delay < ctl->ctl_conn->trans_param.max_ack_delay ?
            ack_delay : ctl->ctl_conn->trans_param.max_ack_delay;
    // Adjust for ack delay if it's plausible.
    if (latest_rtt - ctl->ctl_minrtt > ack_delay) {
        latest_rtt -= ack_delay;
    }
    // Based on {{RFC6298}}.
    if (ctl->ctl_srtt == 0) {
        ctl->ctl_srtt = latest_rtt;
        ctl->ctl_rttvar = latest_rtt >> 1;
    } else {
        /*rttvar_sample = abs(smoothed_rtt - latest_rtt)
         rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
         smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * latest_rtt*/
        ctl->ctl_rttvar -= ctl->ctl_rttvar >> 2;
        ctl->ctl_rttvar += llabs(ctl->ctl_srtt - latest_rtt) >> 2;

        ctl->ctl_srtt -= ctl->ctl_srtt >> 3;
        ctl->ctl_srtt += latest_rtt >> 3;
    }
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|after update rtt|srtt=%ui, rttvar=%ui, minrtt=%ui, latest_rtt=%ui, ack_delay=%ui",
            ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, latest_rtt, ack_delay);
}

