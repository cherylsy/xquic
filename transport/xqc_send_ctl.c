
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_frame.h"
#include "xqc_conn.h"
#include "../common/xqc_timer.h"
#include "../congestion_control/xqc_new_reno.h"


xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;
    send_ctl->ctl_minrtt = XQC_MAX_UINT32_VALUE;

    xqc_init_list_head(&send_ctl->ctl_packets);
    xqc_init_list_head(&send_ctl->ctl_lost_packets);
    xqc_init_list_head(&send_ctl->ctl_free_packets);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_ctl->ctl_unacked_packets[pns]);
    }

    xqc_send_ctl_timer_init(send_ctl);

    if (conn->engine->eng_callback.cong_ctrl_callback.xqc_cong_ctl_init) {
        send_ctl->ctl_cong_callback = &conn->engine->eng_callback.cong_ctrl_callback;
    } else {
        send_ctl->ctl_cong_callback = &xqc_reno_cb;
    }
    send_ctl->ctl_cong = xqc_pcalloc(conn->conn_pool, send_ctl->ctl_cong_callback->xqc_cong_ctl_size());
    send_ctl->ctl_cong_callback->xqc_cong_ctl_init(send_ctl->ctl_cong);

    return send_ctl;
}

void
xqc_send_ctl_destroy(xqc_send_ctl_t *ctl)
{
    xqc_send_ctl_destroy_packets_lists(ctl);
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, xqc_pkt_type_t pkt_type)
{
    xqc_packet_out_t *packet_out;

    xqc_list_head_t *pos;

    xqc_list_for_each_reverse(pos, &ctl->ctl_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type &&
            packet_out->po_buf_size - packet_out->po_used_size >= need) {
            return packet_out;
        }
    }

    packet_out = xqc_create_packet_out(ctl, pkt_type);
    if (packet_out == NULL) {
        return NULL;
    }


    return packet_out;
}

void
xqc_send_ctl_destroy_packets_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_list_del_init(pos);
        xqc_destroy_packet_out(packet_out);
    }
}

void
xqc_send_ctl_destroy_packets_lists(xqc_send_ctl_t *ctl)
{
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_lost_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_free_packets);

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_send_ctl_destroy_packets_list(&ctl->ctl_unacked_packets[pns]);
    }

    ctl->ctl_bytes_in_flight = 0;
    ctl->ctl_crypto_bytes_in_flight = 0;
    ctl->ctl_packets_used = 0;
    ctl->ctl_packets_free = 0;
}

int
xqc_send_ctl_can_send (xqc_connection_t *conn)
{
    int can = 1;
    unsigned congestion_window =
            conn->conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(conn->conn_send_ctl->ctl_cong);
    if (conn->conn_send_ctl->ctl_bytes_in_flight >= congestion_window) {
        can = 0;
    }
    return can;
}

void
xqc_send_ctl_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(&packet_out->po_list);

    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        if (ctl->ctl_bytes_in_flight < packet_out->po_used_size) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|ctl_bytes_in_flight too small|");
            ctl->ctl_bytes_in_flight = 0;
            packet_out->po_flag &= ~XQC_POF_IN_FLIGHT;
            return;
        }
        ctl->ctl_bytes_in_flight -= packet_out->po_used_size;
        if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
            ctl->ctl_crypto_bytes_in_flight -= packet_out->po_used_size;
        }
        packet_out->po_flag &= ~XQC_POF_IN_FLIGHT;
    }
}

void
xqc_send_ctl_insert_unacked(xqc_packet_out_t *packet_out, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(&packet_out->po_list, head);
}

void
xqc_send_ctl_remove_send(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_send(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(pos, head);
    ctl->ctl_packets_used++;
}

void
xqc_send_ctl_remove_lost(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_lost(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_remove_free(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    ctl->ctl_packets_free--;
}

void
xqc_send_ctl_insert_free(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(pos, head);
    ctl->ctl_packets_free++;
    ctl->ctl_packets_used--;
}

void
xqc_send_ctl_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_del_init(pos);
    xqc_list_add(pos, head);
}

void
xqc_send_ctl_drop_packets(xqc_send_ctl_t *ctl)
{
    xqc_send_ctl_destroy_packets_lists(ctl);
}

/* timer callbacks */
void xqc_send_ctl_ack_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_connection_t *conn = ((xqc_send_ctl_t*)ctx)->ctl_conn;
    xqc_pkt_num_space_t pns = type - XQC_TIMER_ACK_INIT;
    conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_ack_timeout|pns=%d|", pns);
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.9
 * OnLossDetectionTimeout
 */
void xqc_send_ctl_loss_detection_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_loss_detection_timeout|");
    xqc_msec_t loss_time;
    xqc_pkt_num_space_t pns;
    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        // Time threshold loss Detection
        xqc_send_ctl_detect_lost(ctl, pns, now);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_loss_detection_timeout|xqc_send_ctl_detect_lost|");
    }
    // Retransmit crypto data if no packets were lost
    // and there are still crypto packets in flight.
    else if (ctl->ctl_crypto_bytes_in_flight) {
        // Crypto retransmission timeout.
        xqc_conn_retransmit_unacked_crypto(ctl->ctl_conn);
        ctl->ctl_crypto_count++;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_loss_detection_timeout|xqc_conn_retransmit_unacked_crypto|");
    }
    else {
        // PTO
        xqc_conn_send_probe_packets(ctl->ctl_conn);
        ctl->ctl_pto_count++;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_loss_detection_timeout|xqc_conn_send_probe_packets|");
    }

    xqc_send_ctl_set_loss_detection_timer(ctl);
}

void xqc_send_ctl_idle_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
}

void xqc_send_ctl_draining_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
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
            timer->ctl_timer_callback = xqc_send_ctl_ack_timeout;
            timer->ctl_ctx = ctl;
        } else if (type == XQC_TIMER_LOSS_DETECTION) {
            timer->ctl_timer_callback = xqc_send_ctl_loss_detection_timeout;
            timer->ctl_ctx = ctl;
        } else if (type == XQC_TIMER_IDLE) {
            timer->ctl_timer_callback = xqc_send_ctl_idle_timeout;
            timer->ctl_ctx = ctl;
        } else if (type == XQC_TIMER_DRAINING) {
            timer->ctl_timer_callback = xqc_send_ctl_draining_timeout;
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
        if (timer->ctl_timer_is_set && timer->ctl_expire_time <= now) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                    "|xqc_send_ctl_timer_expire|type=%d, expire_time=%ui, now=%ui|",
                    type, timer->ctl_expire_time, now);
            timer->ctl_timer_callback(type, now, timer->ctl_ctx);

            //unset timer if it is not updated in ctl_timer_callback
            if (timer->ctl_expire_time <= now) {
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                        "|xqc_send_ctl_timer_expire|unset|type=%d, expire_time=%ui, now=%ui|",
                        type, timer->ctl_expire_time, now);
                xqc_send_ctl_timer_unset(ctl, type);
            }
        }
    }
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.5
 * OnPacketSent
 */
void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    xqc_msec_t now = xqc_gettimeofday();
    packet_out->po_sent_time = now;
    if (packet_out->po_pkt.pkt_num > ctl->ctl_largest_sent) {
        ctl->ctl_largest_sent = packet_out->po_pkt.pkt_num;
    }

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {
        if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
            ctl->ctl_time_of_last_sent_crypto_packet = packet_out->po_sent_time;
        }
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ctl->ctl_time_of_last_sent_ack_eliciting_packet = packet_out->po_sent_time;
            /*
             * The timer is also restarted
             * when sending a packet containing frames other than ACK or PADDING (an
             * ACK-eliciting packet
             */
            xqc_send_ctl_timer_set(ctl, XQC_TIMER_IDLE, now + ctl->ctl_conn->trans_param.idle_timeout);
        }

        if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT)) {
            ctl->ctl_bytes_in_flight += packet_out->po_used_size;
            if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
                ctl->ctl_crypto_bytes_in_flight += packet_out->po_used_size;
            }
            packet_out->po_flag |= XQC_POF_IN_FLIGHT;
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_set_loss_detection_timer(ctl);
        }
    }
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.6
 * OnAckReceived
 */
int
xqc_send_ctl_on_ack_received (xqc_send_ctl_t *ctl, xqc_ack_info_t *const ack_info, xqc_msec_t ack_recv_time)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    unsigned char update_rtt = 0;
    xqc_packet_number_t lagest_ack = ack_info->ranges[0].high;
    xqc_pktno_range_t *range = &ack_info->ranges[ack_info->n_ranges - 1];
    xqc_pkt_num_space_t pns = ack_info->pns;

    if (lagest_ack > ctl->ctl_largest_sent) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_on_ack_received|recv ack is not sent yet");
        return XQC_ERROR;
    }

    packet_out = xqc_list_entry(&ctl->ctl_unacked_packets[pns], xqc_packet_out_t, po_list);
    if (packet_out == NULL) {
        return XQC_OK;
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_num > lagest_ack) {
            break;
        }
        while (packet_out->po_pkt.pkt_num > range->high && range != ack_info->ranges) {
            --range;
        }

        if (packet_out->po_pkt.pkt_num >= range->low) {
            if (packet_out->po_pkt.pkt_num >= ctl->ctl_largest_acked[pns]) {
                ctl->ctl_largest_acked[pns] = packet_out->po_pkt.pkt_num;
                ctl->ctl_largest_acked_sent_time[pns] = packet_out->po_sent_time;
            }

            if (packet_out->po_largest_ack > ctl->ctl_largest_ack_both[pns]) {
                ctl->ctl_largest_ack_both[pns] = packet_out->po_largest_ack;
            }

            xqc_send_ctl_on_packet_acked(ctl, packet_out);

            //remove from unacked list
            xqc_send_ctl_remove_unacked(packet_out, ctl);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);


            if (packet_out->po_pkt.pkt_num == lagest_ack &&
                packet_out->po_pkt.pkt_num == ctl->ctl_largest_acked[pns] &&
                XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                ctl->ctl_latest_rtt = ack_recv_time - ctl->ctl_largest_acked_sent_time[pns];
                update_rtt = 1;
            }

        }
    }

    if (update_rtt) {
        xqc_send_ctl_update_rtt(ctl, &ctl->ctl_latest_rtt, ack_info->ack_delay);
    }

    xqc_send_ctl_detect_lost(ctl, pns, ack_recv_time);

    xqc_recv_record_del(&ctl->ctl_conn->recv_record[pns], ctl->ctl_largest_ack_both[pns] + 1);
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_on_ack_received|xqc_recv_record_del from %ui",
            ctl->ctl_largest_ack_both[pns] + 1);
    xqc_recv_record_log(ctl->ctl_conn, &ctl->ctl_conn->recv_record[pns]);

    ctl->ctl_crypto_count = 0;
    ctl->ctl_pto_count = 0;

    xqc_send_ctl_set_loss_detection_timer(ctl);

    return XQC_OK;
}


/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.6
 * UpdateRtt
 */
void
xqc_send_ctl_update_rtt(xqc_send_ctl_t *ctl, xqc_msec_t *latest_rtt, xqc_msec_t ack_delay)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|before update rtt|srtt=%ui, rttvar=%ui, minrtt=%ui, latest_rtt=%ui, ack_delay=%ui",
            ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);

    // min_rtt ignores ack delay.
    ctl->ctl_minrtt = xqc_min(*latest_rtt, ctl->ctl_minrtt);
    // Limit ack_delay by max_ack_delay
    ack_delay = xqc_min(ack_delay, ctl->ctl_conn->trans_param.max_ack_delay);


    // Adjust for ack delay if it's plausible.
    if (*latest_rtt - ctl->ctl_minrtt > ack_delay) {
        *latest_rtt -= ack_delay;
    }

    // Based on {{RFC6298}}.
    if (ctl->ctl_srtt == 0) {
        ctl->ctl_srtt = *latest_rtt;
        ctl->ctl_rttvar = *latest_rtt >> 1;
    } else {
        /*rttvar_sample = abs(smoothed_rtt - latest_rtt)
         rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
         smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * latest_rtt*/
        ctl->ctl_rttvar -= ctl->ctl_rttvar >> 2;
        ctl->ctl_rttvar += llabs(ctl->ctl_srtt - *latest_rtt) >> 2;

        ctl->ctl_srtt -= ctl->ctl_srtt >> 3;
        ctl->ctl_srtt += *latest_rtt >> 3;
    }

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|after update rtt|srtt=%ui, rttvar=%ui, minrtt=%ui, latest_rtt=%ui, ack_delay=%ui",
            ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.10
 * DetectLostPackets
 */
void
xqc_send_ctl_detect_lost(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pns, xqc_msec_t now)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po, *largest_lost = NULL;
    int is_in_flight;

    ctl->ctl_loss_time[pns] = 0;

    /* loss_delay = 9/8 * max(latest_rtt, smoothed_rtt) */
    xqc_msec_t loss_delay = xqc_max(ctl->ctl_latest_rtt, ctl->ctl_srtt);
    loss_delay += loss_delay >> 3;

    // Packets sent before this time are deemed lost.
    xqc_msec_t lost_send_time = now - loss_delay;

    // Packets with packet numbers before this are deemed lost.
    xqc_packet_number_t  lost_pn = ctl->ctl_largest_acked[pns] - XQC_kPacketThreshold;

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_pkt.pkt_num > ctl->ctl_largest_acked[pns]) {
            continue;
        }

        // Mark packet as lost, or set time when it should be marked.
        if (po->po_sent_time <= lost_send_time || po->po_pkt.pkt_num <= lost_pn) {
            is_in_flight = po->po_flag & XQC_POF_IN_FLIGHT;
            xqc_send_ctl_remove_unacked(po, ctl);
            if (is_in_flight) {
                xqc_send_ctl_insert_lost(pos, &ctl->ctl_lost_packets);
            } else {
                xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            }

            if (largest_lost == NULL) {
                largest_lost = po;
            } else {
                largest_lost = po->po_pkt.pkt_num > largest_lost->po_pkt.pkt_num ? po : largest_lost;
            }
        } else {
            if (ctl->ctl_loss_time[pns] == 0) {
                ctl->ctl_loss_time[pns] = po->po_sent_time + loss_delay;
            } else {
                ctl->ctl_loss_time[pns] = xqc_min(ctl->ctl_loss_time[pns], po->po_sent_time + loss_delay);
            }
        }
    }
    /**
     * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-B.8
     * OnPacketsLost
     */
    if (largest_lost) {
        // Start a new congestion epoch if the last lost packet
        // is past the end of the previous recovery epoch.
        xqc_send_ctl_congestion_event(ctl, largest_lost->po_sent_time);

        // Collapse congestion window if persistent congestion
        if (xqc_send_ctl_in_persistent_congestion(ctl, largest_lost)) {
            ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd(ctl->ctl_cong);
        }
    }
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-B.8
 * InPersistentCongestion
 */
int
xqc_send_ctl_in_persistent_congestion(xqc_send_ctl_t *ctl, xqc_packet_out_t *largest_lost)
{
    xqc_msec_t pto = xqc_send_ctl_calc_pto(ctl);
    xqc_msec_t congestion_period =
            pto * ( xqc_send_ctl_pow(XQC_kPersistentCongestionThreshold) - 1);
    // Determine if all packets in the window before the
    // newest lost packet, including the edges, are marked
    // lost
    return xqc_send_ctl_is_window_lost(ctl, largest_lost, congestion_period);
}

/**
 * https://tools.ietf.org/html/draft-ietf-quic-recovery-19#section-7.7
 * IsWindowLost
 */
int
xqc_send_ctl_is_window_lost(xqc_send_ctl_t *ctl, xqc_packet_out_t *largest_lost, xqc_msec_t congestion_period)
{
    //TODO: 有疑问
    xqc_list_head_t *pos;
    xqc_packet_out_t *packet_out, *smallest_lost_in_period = NULL;
    unsigned in_period_num = 0;

    xqc_list_for_each(pos, &ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (smallest_lost_in_period == NULL) {
            smallest_lost_in_period = packet_out;
        } else if (packet_out->po_pkt.pkt_num < smallest_lost_in_period->po_pkt.pkt_num) {
            smallest_lost_in_period = packet_out;
        }

        if (packet_out->po_sent_time < largest_lost->po_sent_time) {
            ++in_period_num;
        }
    }

    if (largest_lost->po_pkt.pkt_num - smallest_lost_in_period->po_pkt.pkt_num == in_period_num &&
            largest_lost->po_sent_time - smallest_lost_in_period->po_sent_time >= congestion_period) {
        return 1;
    }
    return 0;
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-B.6
 * CongestionEvent
 */
void
xqc_send_ctl_congestion_event(xqc_send_ctl_t *ctl, xqc_msec_t sent_time)
{

    ctl->ctl_cong_callback->xqc_cong_ctl_on_lost(ctl->ctl_cong, sent_time);
}


/**
 * IsAppLimited
 */
int
xqc_send_ctl_is_app_limited()
{
    return 0;
}

/**
 * OnPacketAckedCC
 */
void
xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *ctl, xqc_packet_out_t *acked_packet)
{
    if (xqc_send_ctl_is_app_limited()) {
        // Do not increase congestion_window if application
        // limited.
        return;
    }

    ctl->ctl_cong_callback->xqc_cong_ctl_on_ack(ctl->ctl_cong, acked_packet->po_sent_time, acked_packet->po_used_size);

}


/**
 * SetLossDetectionTimer
 */
void
xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *ctl)
{
    xqc_pkt_num_space_t pns;
    xqc_msec_t loss_time, timeout;

    xqc_connection_t *conn = ctl->ctl_conn;

    // Don't arm timer if there are no ack-eliciting packets
    // in flight.
    if (0 == ctl->ctl_bytes_in_flight) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_set_loss_detection_timer|unset|no data in flight|");
        xqc_send_ctl_timer_unset(ctl, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|ctl_bytes_in_flight %ui|",
            ctl->ctl_bytes_in_flight);

    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        // Time threshold loss detection.
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION, loss_time);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|xqc_send_ctl_set_loss_detection_timer|xqc_send_ctl_timer_set|loss_time=%ui|",
                loss_time);
        return;
    }

    if (ctl->ctl_crypto_bytes_in_flight > 0) {
        // Crypto retransmission timer.
        if (ctl->ctl_srtt == 0) {
            timeout = 2 * XQC_kInitialRtt;
        }
        else {
            timeout = 2 * ctl->ctl_srtt;
        }
        timeout = xqc_max(timeout, XQC_kGranularity);
        timeout = timeout * xqc_send_ctl_pow(ctl->ctl_crypto_count);
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION,
                ctl->ctl_time_of_last_sent_crypto_packet + timeout);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|xqc_send_ctl_set_loss_detection_timer|xqc_send_ctl_timer_set|ctl_time_of_last_sent_crypto_packet=%ui, timeout=%ui|",
                ctl->ctl_time_of_last_sent_crypto_packet, timeout);
        return;
    }
    // Calculate PTO duration
    timeout = ctl->ctl_srtt + xqc_max(4 * ctl->ctl_rttvar, XQC_kGranularity) + ctl->ctl_conn->trans_param.max_ack_delay;

    timeout = timeout * xqc_send_ctl_pow(ctl->ctl_pto_count);

    xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION,
            ctl->ctl_time_of_last_sent_ack_eliciting_packet + timeout);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|xqc_send_ctl_set_loss_detection_timer|xqc_send_ctl_timer_set|ctl_time_of_last_sent_ack_eliciting_packet=%ui, timeout=%ui|",
            ctl->ctl_time_of_last_sent_ack_eliciting_packet, timeout);
}

/**
 * GetEarliestLossTime
 *
 * Returns the earliest loss_time and the packet number
 * space it's from.  Returns 0 if all times are 0.
 */
xqc_msec_t
xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t *pns_ret)
{
    xqc_msec_t time = ctl->ctl_loss_time[XQC_PNS_INIT];
    *pns_ret = XQC_PNS_INIT;
    for ( xqc_pkt_num_space_t pns = XQC_PNS_HSK; pns < XQC_PNS_01RTT; ++pns) {
        if (ctl->ctl_loss_time[pns] != 0 &&
                (time == 0 || ctl->ctl_loss_time[pns] < time) ) {
            time = ctl->ctl_loss_time[pns];
            *pns_ret = pns;
        }
    }
    return time;
}
