
#include "congestion_control/xqc_bbr.h"
#include "xqc_engine.h"
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_frame.h"
#include "xqc_conn.h"
#include "xqc_stream.h"
#include "common/xqc_timer.h"
#include "common/xqc_memory_pool.h"
#include "congestion_control/xqc_sample.h"


xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    uint64_t now = xqc_now();
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;
    send_ctl->ctl_minrtt = XQC_MAX_UINT32_VALUE;
    send_ctl->ctl_delivered = 0;

    xqc_init_list_head(&send_ctl->ctl_send_packets);
    xqc_init_list_head(&send_ctl->ctl_send_packets_high_pri);
    xqc_init_list_head(&send_ctl->ctl_lost_packets);
    xqc_init_list_head(&send_ctl->ctl_free_packets);
    xqc_init_list_head(&send_ctl->ctl_buff_1rtt_packets);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_ctl->ctl_unacked_packets[pns]);
    }

    send_ctl->ctl_packets_used_max = XQC_CTL_PACKETS_USED_MAX;

    xqc_send_ctl_timer_init(send_ctl);

    xqc_send_ctl_timer_set(send_ctl, XQC_TIMER_IDLE,
                           now + send_ctl->ctl_conn->local_settings.idle_timeout * 1000);

    if (conn->conn_settings.ping_on && conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_send_ctl_timer_set(send_ctl, XQC_TIMER_PING, now + XQC_PING_TIMEOUT * 1000);
    }

    if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init_bbr) {
        send_ctl->ctl_cong_callback = &conn->conn_settings.cong_ctrl_callback;
    } else if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init) {
        send_ctl->ctl_cong_callback = &conn->conn_settings.cong_ctrl_callback;
    } else {
        send_ctl->ctl_cong_callback = &xqc_cubic_cb;
    }
    send_ctl->ctl_cong = xqc_pcalloc(conn->conn_pool, send_ctl->ctl_cong_callback->xqc_cong_ctl_size());

    if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init_bbr) {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr(send_ctl->ctl_cong, &send_ctl->sampler);
    } else {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_init(send_ctl->ctl_cong);
    }

    xqc_pacing_init(&send_ctl->ctl_pacing, conn->conn_settings.pacing_on, send_ctl);

    send_ctl->ctl_info.record_interval = XQC_DEFAULT_RECORD_INTERVAL;
    send_ctl->ctl_info.last_record_time = 0;
    send_ctl->ctl_info.last_rtt_time = 0;
    send_ctl->ctl_info.last_lost_time = 0;
    send_ctl->ctl_info.last_bw_time = 0;
    send_ctl->ctl_info.rtt_change_threshold = XQC_DEFAULT_RTT_CHANGE_THRESHOLD;
    send_ctl->ctl_info.bw_change_threshold = XQC_DEFAULT_BW_CHANGE_THRESHOLD;

    send_ctl->sampler.send_ctl = send_ctl;

    return send_ctl;
}

void
xqc_send_ctl_destroy(xqc_send_ctl_t *ctl)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|destroy|");
    xqc_send_ctl_destroy_packets_lists(ctl);
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, xqc_pkt_type_t pkt_type)
{
    xqc_packet_out_t *packet_out;

    xqc_list_head_t *pos;

    xqc_list_for_each_reverse(pos, &ctl->ctl_send_packets) {
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
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_send_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_send_packets_high_pri);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_lost_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_free_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_buff_1rtt_packets);

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_send_ctl_destroy_packets_list(&ctl->ctl_unacked_packets[pns]);
    }

    ctl->ctl_bytes_in_flight = 0;
    ctl->ctl_packets_used = 0;
    ctl->ctl_packets_free = 0;
}

void 
xqc_send_ctl_info_circle_record(xqc_connection_t *conn){

    if(conn->conn_type != XQC_CONN_TYPE_SERVER){
        return; //client do not need record
    }
    xqc_send_ctl_t * conn_send_ctl = conn->conn_send_ctl;
    xqc_send_ctl_info_t *ctl_info  = &conn_send_ctl->ctl_info;

    //xqc_conn_log(conn, XQC_LOG_STATS, "|last_record_time:%ui| ctl_info->record_interval:%ui|", ctl_info->last_record_time,ctl_info->record_interval);
    xqc_msec_t now = xqc_now();
    if(ctl_info->record_interval < 10000){ //最低10ms间隔，避免日志泛滥
        return;
    }

    if(ctl_info->last_record_time + ctl_info->record_interval > now){ //未到记录时间
        return;
    }
    ctl_info->last_record_time = now;

    uint64_t cwnd = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(conn_send_ctl->ctl_cong);

    uint64_t bw = 0;
    uint64_t pacing_rate = 0;
    xqc_bbr_t *bbr = NULL;
    int mode = 0;
    xqc_msec_t min_rtt = 0;
    if(conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr){
        bbr = (xqc_bbr_t*)(conn_send_ctl->ctl_cong);
        bw = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(conn_send_ctl->ctl_cong);
        pacing_rate = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(conn_send_ctl->ctl_cong);
        mode = bbr->mode;
        min_rtt = bbr->min_rtt;
    }

    uint64_t srtt = conn_send_ctl->ctl_srtt;
    xqc_conn_log(conn, XQC_LOG_STATS,
                 "|cwnd:%ui|inflight:%ud|mode:%ud|applimit:%ud|pacing_rate:%ui|bw:%ui|srtt:%ui|latest_rtt:%ui|min_rtt:%ui|send:%ud|lost:%ud|conn_life:%ui|",
                 cwnd, conn_send_ctl->ctl_bytes_in_flight,
                 mode, conn_send_ctl->sampler.is_app_limited, pacing_rate, bw,
                 srtt, conn_send_ctl->ctl_latest_rtt, min_rtt,
                 conn_send_ctl->ctl_send_count, conn_send_ctl->ctl_lost_count,
                 now - conn->conn_create_time);

}

/*
 * 拥塞检查
 * QUIC's congestion control is based on TCP NewReno [RFC6582].  NewReno
   is a congestion window based congestion control.  QUIC specifies the
   congestion window in bytes rather than packets due to finer control
   and the ease of appropriate byte counting [RFC3465].

   QUIC hosts MUST NOT send packets if they would increase
   bytes_in_flight (defined in Appendix B.2) beyond the available
   congestion window, unless the packet is a probe packet sent after a
   PTO timer expires, as described in Section 6.3.

   Implementations MAY use other congestion control algorithms, such as
   Cubic [RFC8312], and endpoints MAY use different algorithms from one
   another.  The signals QUIC provides for congestion control are
   generic and are designed to support different algorithms.
 */
int
xqc_send_ctl_can_send (xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    int can = 1;
    unsigned congestion_window =
            conn->conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(conn->conn_send_ctl->ctl_cong);
    if (conn->conn_send_ctl->ctl_bytes_in_flight + packet_out->po_used_size > congestion_window) {
        can = 0;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TOKEN_OK) && !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)
          && conn->conn_type == XQC_CONN_TYPE_SERVER
          && conn->conn_send_ctl->ctl_bytes_send > 3 * conn->conn_send_ctl->ctl_bytes_recv) {
        can = 0;
    }
    xqc_conn_log(conn, XQC_LOG_DEBUG, "|can:%d|inflight:%ud|cwnd:%ud|conn:%p|",
            can, conn->conn_send_ctl->ctl_bytes_in_flight, congestion_window, conn);

    return can;
}


void
xqc_send_ctl_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(&packet_out->po_list);

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
xqc_send_ctl_remove_buff(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    ctl->ctl_packets_used--;
}

void
xqc_send_ctl_insert_buff(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_del_init(pos);
    xqc_list_add(pos, head);
}

void
xqc_send_ctl_move_to_high_pri(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    xqc_list_add_tail(pos, &ctl->ctl_send_packets_high_pri);
}

void
xqc_send_ctl_drop_packets(xqc_send_ctl_t *ctl)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_bytes_in_flight:%ui|"
                                               "ctl_packets_used:%ud|ctl_packets_free:%ud|",
            ctl->ctl_bytes_in_flight, ctl->ctl_packets_used, ctl->ctl_packets_free);
    xqc_send_ctl_destroy_packets_lists(ctl);
}

void
xqc_send_ctl_drop_0rtt_packets(xqc_send_ctl_t *ctl)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[XQC_PNS_01RTT]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_unacked(packet_out, ctl);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            if (ctl->ctl_bytes_in_flight >= packet_out->po_used_size) {
                ctl->ctl_bytes_in_flight -= packet_out->po_used_size;
            } else {
                ctl->ctl_bytes_in_flight = 0;
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_send(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_lost(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        }
    }
}


/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.5
 * OnPacketSent
 */
void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out, xqc_msec_t now)
{
    //printf("send packet_out: %p\n", packet_out);
    xqc_pkt_num_space_t pns = packet_out->po_pkt.pkt_pns;

    xqc_sample_on_sent(packet_out, ctl, now);

    if (packet_out->po_pkt.pkt_num > ctl->ctl_largest_sent[pns]) {
        ctl->ctl_largest_sent[pns] = packet_out->po_pkt.pkt_num;
    }

    ctl->ctl_bytes_send += packet_out->po_used_size;

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] = packet_out->po_sent_time;
            ctl->ctl_last_sent_ack_eliciting_packet_number[pns] = packet_out->po_pkt.pkt_num;
            /*
             * The timer is also restarted
             * when sending a packet containing frames other than ACK or PADDING (an
             * ACK-eliciting packet
             */
            //udp无法识别是否真正发送到对端，避免重传一直刷新idle时间
            //xqc_send_ctl_timer_set(ctl, XQC_TIMER_IDLE, now + ctl->ctl_conn->local_settings.idle_timeout * 1000);
        }

        /*add here RestartfromIdle here*/
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|inflight:%ud|applimit:%ui|", ctl->ctl_bytes_in_flight, ctl->ctl_app_limited);
        if (ctl->ctl_bytes_in_flight == 0 && ctl->ctl_app_limited > 0) {
            if (ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle) {
                /*Just From Debug*/
                xqc_bbr_t *bbr = (xqc_bbr_t*)ctl->ctl_cong;
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|BeforeRestartFromIdle|mode %ud|idle %ud|bw %ud|pacing rate %ud|",
                    bbr->mode, bbr->idle_restart, ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                    ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong));
                ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle(ctl->ctl_cong);
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|AfterRestartFromIdle|mode %ud|idle %ud|bw %ud|pacing rate %ud|",
                    bbr->mode, bbr->idle_restart, ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                    ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong));
            }
        }

        if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT)) {
            ctl->ctl_bytes_in_flight += packet_out->po_used_size;

            if ((packet_out->po_frame_types & XQC_FRAME_BIT_STREAM) &&
                !(packet_out->po_flag & XQC_POF_STREAM_UNACK)) {
                xqc_stream_t *stream;
                for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                    stream = packet_out->po_stream_frames[i].ps_stream;
                    if (stream != NULL) {
                        stream->stream_unacked_pkt++;
                        if (stream->stream_state_send == XQC_SEND_STREAM_ST_READY) {
                            stream->stream_state_send = XQC_SEND_STREAM_ST_SEND;
                        }
                        if (packet_out->po_stream_frames[i].ps_has_fin
                                && stream->stream_state_send == XQC_SEND_STREAM_ST_SEND) {
                            stream->stream_state_send = XQC_SEND_STREAM_ST_DATA_SENT;
                        }
                    } else {
                        break;
                    }
                }
                packet_out->po_flag |= XQC_POF_STREAM_UNACK;
            }
            packet_out->po_flag |= XQC_POF_IN_FLIGHT;
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_set_loss_detection_timer(ctl);
        }

        if (packet_out->po_flag & XQC_POF_LOST) {
            ++ctl->ctl_lost_count;
            packet_out->po_flag &= ~XQC_POF_LOST;
        } else if (packet_out->po_flag & XQC_POF_TLP) {
            ++ctl->ctl_tlp_count;
            packet_out->po_flag &= ~XQC_POF_TLP;
        }
        ++ctl->ctl_send_count;

    }

//    if (xqc_pacing_is_on(&ctl->ctl_pacing) && ctl->ctl_pacing.ref) {
//        ctl->ctl_pacing.ref = 0;
//        xqc_pacing_on_packet_sent(&ctl->ctl_pacing, ctl, ctl->ctl_conn, packet_out);
//    }

}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.6F
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
    unsigned char need_del_record = 0;
    int stream_frame_acked = 0;
    ctl->ctl_prior_delivered = ctl->ctl_delivered;
    ctl->ctl_prior_bytes_in_flight = ctl->ctl_bytes_in_flight;

    if (lagest_ack > ctl->ctl_largest_sent[pns]) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|acked pkt is not sent yet|%ui|", lagest_ack);
        return -XQC_EPROTO;
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
                need_del_record = 1;
            }

            if (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM) {
                stream_frame_acked = 1;
                xqc_update_sample(&ctl->sampler, packet_out, ctl, ack_recv_time);
            }

            xqc_send_ctl_on_packet_acked(ctl, packet_out);

            //remove from unacked list
            xqc_send_ctl_remove_unacked(packet_out, ctl);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);


            if (packet_out->po_pkt.pkt_num == lagest_ack &&
                packet_out->po_pkt.pkt_num == ctl->ctl_largest_acked[pns] &&
                XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                if(ctl->ctl_last_sent_ack_eliciting_packet_number[pns] == packet_out->po_pkt.pkt_num) {
                    ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] = 0;
                }
                ctl->ctl_latest_rtt = ack_recv_time - ctl->ctl_largest_acked_sent_time[pns];
                update_rtt = 1;
            }

        }
    }

    if (update_rtt) {
        if (pns == XQC_PNS_01RTT) {
            xqc_send_ctl_update_rtt(ctl, &ctl->ctl_latest_rtt, ack_info->ack_delay);
        } else {
            /* 握手包回ack会有比较大延迟，计算srtt时忽略ack_delay, 得到真正耗时，避免重传 */
            xqc_send_ctl_update_rtt(ctl, &ctl->ctl_latest_rtt, 0);
        }
    }
    
    xqc_send_ctl_detect_lost(ctl, pns, ack_recv_time);

    if (need_del_record) {
        xqc_recv_record_del(&ctl->ctl_conn->recv_record[pns], ctl->ctl_largest_ack_both[pns] + 1);
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_recv_record_del from %ui|pns:%d|",
                ctl->ctl_largest_ack_both[pns] + 1, pns);
    }

    xqc_recv_record_log(ctl->ctl_conn, &ctl->ctl_conn->recv_record[pns]);

    ctl->ctl_pto_count = 0;

    xqc_send_ctl_set_loss_detection_timer(ctl);

    if(ctl->ctl_cong_callback->xqc_cong_ctl_bbr && stream_frame_acked) {

        xqc_generate_sample(&ctl->sampler, ctl, ack_recv_time);

        uint64_t bw_before = 0, bw_after = 0;
        int bw_record_flag = 0;
        xqc_msec_t now = xqc_now();
        if((ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate != NULL) &&
        (ctl->ctl_info.last_bw_time + ctl->ctl_info.record_interval <= now)){
            bw_before = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
            if(bw_before != 0 ){
                bw_record_flag = 1;
            }
        }

        ctl->ctl_cong_callback->xqc_cong_ctl_bbr(ctl->ctl_cong, &ctl->sampler);
        xqc_bbr_t *bbr = (xqc_bbr_t*)(ctl->ctl_cong);
        xqc_log(ctl->ctl_conn->log, XQC_LOG_INFO,
                "|bbr on ack|mode:%ud|pacing_rate:%ud|bw:%ud|cwnd:%ud|full_bw_reached:%ud"
                "|inflight:%ud|srtt:%ui|latest_rtt:%ui|min_rtt:%ui|applimit:%ud|lost:%ud"
                "|recovery:%ud|recovery_start:%ui|idle_restart:%ud|packet_conservation:%ud|",
                bbr->mode,
                ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong),
                ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong),
                bbr->full_bandwidth_reached,
                ctl->ctl_bytes_in_flight,
                ctl->ctl_srtt, ctl->ctl_latest_rtt, bbr->min_rtt,
                ctl->sampler.is_app_limited, ctl->ctl_lost_count,
                bbr->recovery_mode, bbr->recovery_start_time, bbr->idle_restart, bbr->packet_conservation);
        // xqc_log(ctl->ctl_conn->log, XQC_LOG_INFO,
        //         "|sock: 123456, est.bw: %ud, pacing_rate: %ud, cwnd: %ud, srtt: %ui, rack.rtt: %ui, min_rtt: %ui,"
        //         "pacing_gain: %.2f, cwnd_gain: %.2f",
        //         ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
        //         ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong),
        //         ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong),
        //         ctl->ctl_srtt, ctl->ctl_latest_rtt, bbr->min_rtt,
        //         bbr->pacing_gain, bbr->cwnd_gain);

        if(bw_record_flag){
            bw_after = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
            if(bw_after > 0){
                if(xqc_sub_abs(bw_after, bw_before) * 100 > (bw_before * ctl->ctl_info.bw_change_threshold)){

                    ctl->ctl_info.last_bw_time = now;
                    xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS, "|bandwidth change record|bw_before:%ui|bw_after:%ui|srtt:%ui|cwnd:%ui|",bw_before, bw_after, ctl->ctl_srtt, ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong));
                }
            }

        }

        ctl->sampler.prior_time = 0;
    }

    xqc_send_ctl_info_circle_record(ctl->ctl_conn);
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
            "|before update rtt|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
            ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);

    // min_rtt ignores ack delay.
    ctl->ctl_minrtt = xqc_min(*latest_rtt, ctl->ctl_minrtt);
    // Limit ack_delay by max_ack_delay
    ack_delay = xqc_min(ack_delay, ctl->ctl_conn->local_settings.max_ack_delay * 1000);


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
        uint64_t srtt = ctl->ctl_srtt;
        uint64_t rttvar = ctl->ctl_rttvar;
        ctl->ctl_rttvar -= ctl->ctl_rttvar >> 2;
        ctl->ctl_rttvar += (ctl->ctl_srtt > *latest_rtt ? ctl->ctl_srtt - *latest_rtt : *latest_rtt - ctl->ctl_srtt) >> 2;

        ctl->ctl_srtt -= ctl->ctl_srtt >> 3;
        ctl->ctl_srtt += *latest_rtt >> 3;

        if(xqc_sub_abs(ctl->ctl_srtt, srtt)  > ctl->ctl_info.rtt_change_threshold){

            xqc_msec_t now = xqc_now();
            if(ctl->ctl_info.last_rtt_time + ctl->ctl_info.record_interval <= now){
                ctl->ctl_info.last_rtt_time = now;
                xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS, "|before update rtt|srtt:%ui|rttvar:%ui|after update rtt|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
                        srtt, rttvar, ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);
            }
        }
    }

    xqc_conn_log(ctl->ctl_conn, XQC_LOG_DEBUG,
            "|after update rtt|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
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
    uint64_t lost_n = 0;

    ctl->ctl_loss_time[pns] = 0;

    ctl->sampler.loss = 0;

    /* loss_delay = 9/8 * max(latest_rtt, smoothed_rtt) */
    xqc_msec_t loss_delay = xqc_max(ctl->ctl_latest_rtt, ctl->ctl_srtt);
    loss_delay += loss_delay >> 3;

    // Packets sent before this time are deemed lost.
    xqc_msec_t lost_send_time = now - loss_delay;

    // Packets with packet numbers before this are deemed lost.
    xqc_packet_number_t  lost_pn = ctl->ctl_largest_acked[pns] - XQC_kPacketThreshold;

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_largest_acked:%ui|pns:%ui|", ctl->ctl_largest_acked[pns], pns);

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_pkt.pkt_num > ctl->ctl_largest_acked[pns]) {
            continue;
        }

        // Mark packet as lost, or set time when it should be marked.
        if (po->po_sent_time <= lost_send_time || po->po_pkt.pkt_num <= lost_pn) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                    "|mark lost|pns:%d|pkt_num:%ui|lost_pn:%ui|po_sent_time:%ui|lost_send_time:%ui|loss_delay:%ui|frame:%s|",
                pns, po->po_pkt.pkt_num, lost_pn, po->po_sent_time, lost_send_time, loss_delay, xqc_frame_type_2_str(po->po_frame_types));
            is_in_flight = po->po_flag & XQC_POF_IN_FLIGHT;
            xqc_send_ctl_remove_unacked(po, ctl);
            if (is_in_flight) {
                xqc_send_ctl_insert_lost(pos, &ctl->ctl_lost_packets);
                lost_n++;
                //substract the length of the lost packet from bytes_in_flight
                //clear inflight flag
                ctl->ctl_bytes_in_flight -= po->po_used_size;
                po->po_flag &= ~XQC_POF_IN_FLIGHT;
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
    ctl->sampler.loss = lost_n;
    /**
     * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-B.8
     * OnPacketsLost
     */
    if (largest_lost) {
        // Start a new congestion epoch if the last lost packet
        // is past the end of the previous recovery epoch.
        // enter loss recovery here
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|OnLostDetection|largest_lost sent time: %lu|", largest_lost->po_sent_time);
        xqc_send_ctl_congestion_event(ctl, largest_lost->po_sent_time);

        // Collapse congestion window if persistent congestion
        if (ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd &&
            xqc_send_ctl_in_persistent_congestion(ctl, largest_lost)) {
            //we reset BBR's cwnd here
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|OnLostDetection|%s|", "Persistent congestion occurs");
            ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd(ctl->ctl_cong);
        }

        xqc_msec_t now = xqc_now();
        if(ctl->ctl_info.last_lost_time + ctl->ctl_info.record_interval <= now){
            xqc_msec_t lost_interval = now - ctl->ctl_info.last_lost_time;
            ctl->ctl_info.last_lost_time = now;
            uint64_t lost_count = ctl->ctl_lost_count + lost_n - ctl->ctl_info.last_lost_count;
            uint64_t send_count = ctl->ctl_send_count - ctl->ctl_info.last_send_count;
            ctl->ctl_info.last_lost_count = ctl->ctl_lost_count + lost_n;
            ctl->ctl_info.last_send_count = ctl->ctl_send_count;
            uint64_t bw = 0;
            if(ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate){
                bw = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
            }
            xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS, "|lost interval:%ui|lost_count:%ui|send_count:%ui|pkt_num:%ui|po_send_time:%ui|srtt:%ui|cwnd:%ud|bw:%ui|conn_life:%ui|",
                         lost_interval, lost_count, send_count, largest_lost->po_pkt.pkt_num, largest_lost->po_sent_time, ctl->ctl_srtt,
                         ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong), bw, now - ctl->ctl_conn->conn_create_time);
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
    xqc_list_head_t *pos;
    xqc_packet_out_t *packet_out, *smallest_lost_in_period = NULL;
    unsigned lost_pkts_in_between = 0;

    //we should keep the ctl_lost_packets ordered by pkt_num to avoid this loop
    xqc_list_for_each(pos, &ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (smallest_lost_in_period == NULL) {
            smallest_lost_in_period = packet_out;
        } else if (packet_out->po_pkt.pkt_num < smallest_lost_in_period->po_pkt.pkt_num) {
            smallest_lost_in_period = packet_out;
        }
    }

    //first of all, the sending interval between the smallest and the largest must be >= congestion_period
    if (largest_lost->po_sent_time - smallest_lost_in_period->po_sent_time >= congestion_period) {
        //check if all pkts between the smallest and the largest are lost
        xqc_list_for_each(pos, &ctl->ctl_lost_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_num >= smallest_lost_in_period->po_pkt.pkt_num 
                && packet_out->po_pkt.pkt_num < largest_lost->po_pkt.pkt_num) 
            {   
                lost_pkts_in_between++;
            }
        }
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|InPresistentCongestion|largest.pn %ui|smallest.pn %ui"
            "|largest sent time %ui|smallest sent time %ui|lost pkts in between %ud|",
            largest_lost->po_pkt.pkt_num, smallest_lost_in_period->po_pkt.pkt_num,
            largest_lost->po_sent_time, smallest_lost_in_period->po_sent_time,
            lost_pkts_in_between);
        //i.e. 1, 2, 3 are lost. lost_pkts_in_between = 2
        if (lost_pkts_in_between == (largest_lost->po_pkt.pkt_num - smallest_lost_in_period->po_pkt.pkt_num))
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
    if (ctl->ctl_cong_callback->xqc_cong_ctl_on_lost) {
        ctl->ctl_cong_callback->xqc_cong_ctl_on_lost(ctl->ctl_cong, sent_time);
    }
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
    xqc_stream_t *stream;
    xqc_packet_out_t *packet_out = acked_packet;
    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        if (ctl->ctl_bytes_in_flight < packet_out->po_used_size) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|ctl_bytes_in_flight too small|");
            ctl->ctl_bytes_in_flight = 0;
        } else {
            ctl->ctl_bytes_in_flight -= packet_out->po_used_size;
        }

        if ((packet_out->po_frame_types & XQC_FRAME_BIT_STREAM) 
            && (packet_out->po_flag & XQC_POF_STREAM_UNACK)) 
        {
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                stream = packet_out->po_stream_frames[i].ps_stream;
                if (stream != NULL) {
                    if (stream->stream_unacked_pkt == 0) {
                        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|stream_unacked_pkt too small|");
                    } else {
                        stream->stream_unacked_pkt--;
                    }
                } else {
                    break;
                }

                if (stream->stream_unacked_pkt == 0 && stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT) {
                    stream->stream_state_send = XQC_SEND_STREAM_ST_DATA_RECVD;
                    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|stream enter DATA RECVD|");
                    xqc_stream_maybe_need_close(stream);
                }
            }
            packet_out->po_flag &= ~XQC_POF_STREAM_UNACK;
        }
        if (packet_out->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                stream = packet_out->po_stream_frames[i].ps_stream;
                if (stream != NULL && packet_out->po_stream_frames[i].ps_is_reset) {
                    if (stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT) {
                        stream->stream_state_send = XQC_SEND_STREAM_ST_RESET_RECVD;
                        xqc_stream_maybe_need_close(stream);
                    }
                }
            }
        }
        if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO && packet_out->po_pkt.pkt_pns == XQC_PNS_HSK) {
            ctl->ctl_conn->conn_flag |= XQC_CONN_FLAG_HSK_ACKED;
        }
        if (packet_out->po_frame_types & XQC_FRAME_BIT_PING) {
            if (ctl->ctl_conn->conn_callbacks.conn_ping_acked && packet_out->ping_user_data) {
                ctl->ctl_conn->conn_callbacks.conn_ping_acked(ctl->ctl_conn, &ctl->ctl_conn->scid,
                                                              ctl->ctl_conn->user_data,
                                                              packet_out->ping_user_data);
            }
        }

        packet_out->po_flag &= ~XQC_POF_IN_FLIGHT;
    }

    if (xqc_send_ctl_is_app_limited()) {
        // Do not increase congestion_window if application
        // limited.
        return;
    }

    if (ctl->ctl_cong_callback->xqc_cong_ctl_on_ack) {
        ctl->ctl_cong_callback->xqc_cong_ctl_on_ack(ctl->ctl_cong, acked_packet->po_sent_time,
                                                    acked_packet->po_used_size);
    }
}

xqc_msec_t
xqc_send_ctl_get_earliest_time_of_last_sent_ack_eliciting_packet(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t *pns_ret)
{
    xqc_msec_t time = ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_INIT];
    *pns_ret = XQC_PNS_INIT;
    for ( xqc_pkt_num_space_t pns = XQC_PNS_HSK; pns <= XQC_PNS_01RTT; ++pns) {
        if (ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] != 0 &&
                (time == 0 || ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] < time) ) {
            time = ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns];
            *pns_ret = pns;
        }
    }
    return time;
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

    /*xqc_log(conn->log, XQC_LOG_DEBUG,
            "|ctl_bytes_in_flight:%ui|",
            ctl->ctl_bytes_in_flight);*/

    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        // Time threshold loss detection.
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION, loss_time);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|xqc_send_ctl_timer_set|loss_time:%ui|",
                loss_time);
        return;
    }

    // Don't arm timer if there are no ack-eliciting packets
    // in flight.
    if (0 == ctl->ctl_bytes_in_flight) { //TODO: &&PeerNotAwaitingAddressValidation
        xqc_log(conn->log, XQC_LOG_DEBUG, "|unset|no data in flight|");
        xqc_send_ctl_timer_unset(ctl, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    // Calculate PTO duration
    if (ctl->ctl_srtt == 0) {
        timeout = 2 * XQC_kInitialRtt * 1000;
    } else if (ctl->ctl_srtt == ctl->ctl_latest_rtt && ctl->ctl_rttvar == ctl->ctl_srtt >> 1) { //第一次计算出的rttvar=srtt/2值比较大
        timeout = ctl->ctl_srtt + xqc_max(1 * ctl->ctl_rttvar, XQC_kGranularity * 1000) +
                  ctl->ctl_conn->local_settings.max_ack_delay * 1000;
    } else {
        timeout = xqc_send_ctl_calc_pto(ctl);
    }
    timeout = timeout * xqc_send_ctl_pow(ctl->ctl_pto_count);

    xqc_msec_t ack_eliciting_send_time = xqc_send_ctl_get_earliest_time_of_last_sent_ack_eliciting_packet(ctl, &pns);
    //only start PTO timer if there are ack_eliciting packets in flight.
    if (ack_eliciting_send_time != 0) {
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION,
            ack_eliciting_send_time + timeout);
        xqc_log(conn->log, XQC_LOG_DEBUG,
            "|PTO|xqc_send_ctl_timer_set|ctl_time_of_last_sent_ack_eliciting_packet:%ui|pto_count:%ud|timeout:%ui|",
            ack_eliciting_send_time, ctl->ctl_pto_count, timeout);
    }
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
    for ( xqc_pkt_num_space_t pns = XQC_PNS_HSK; pns <= XQC_PNS_01RTT; ++pns) {
        if (ctl->ctl_loss_time[pns] != 0 &&
                (time == 0 || ctl->ctl_loss_time[pns] < time) ) {
            time = ctl->ctl_loss_time[pns];
            *pns_ret = pns;
        }
    }
    return time;
}



xqc_msec_t
xqc_send_ctl_get_srtt(xqc_send_ctl_t *ctl)
{
    return ctl->ctl_srtt;
}

float
xqc_send_ctl_get_retrans_rate(xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_send_count <= 0) {
        return 0.0f;
    } else {
        return (float)(ctl->ctl_lost_count + ctl->ctl_tlp_count) / ctl->ctl_send_count;
    }
}

/*
 * *****************TIMER*****************
 */
static const char * const timer_type_2_str[XQC_TIMER_N] = {
        [XQC_TIMER_ACK_INIT]    = "ACK_INIT",
        [XQC_TIMER_ACK_HSK]     = "ACK_HSK",
        [XQC_TIMER_ACK_01RTT]   = "ACK_01RTT",
        [XQC_TIMER_LOSS_DETECTION] = "LOSS_DETECTION",
        [XQC_TIMER_IDLE]        = "IDLE",
        [XQC_TIMER_DRAINING]    = "DRAINING",
        [XQC_TIMER_PACING]      = "PACING",
        [XQC_TIMER_STREAM_CLOSE]= "STREAM_CLOSE",
        [XQC_TIMER_PING]        = "PING",
};

const char *
xqc_timer_type_2_str(xqc_send_ctl_timer_type timer_type)
{
    return timer_type_2_str[timer_type];
}

/* timer callbacks */
void
xqc_send_ctl_ack_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_connection_t *conn = ((xqc_send_ctl_t*)ctx)->ctl_conn;
    xqc_pkt_num_space_t pns = type - XQC_TIMER_ACK_INIT;
    conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|pns:%d|", pns);
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-A.9
 * OnLossDetectionTimeout
 */
void
xqc_send_ctl_loss_detection_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|loss_detection_timeout|");
    xqc_msec_t loss_time;
    xqc_pkt_num_space_t pns;
    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_detect_lost|");
        // Time threshold loss Detection
        xqc_send_ctl_detect_lost(ctl, pns, now);
        xqc_send_ctl_set_loss_detection_timer(ctl);
        return;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_conn_send_probe_packets|");
    // PTO
    xqc_conn_send_probe_packets(ctl->ctl_conn);

    ctl->ctl_pto_count++;
    xqc_send_ctl_set_loss_detection_timer(ctl);
}

void
xqc_send_ctl_idle_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
}

void
xqc_send_ctl_draining_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
}

void
xqc_send_ctl_pacing_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    ctl->ctl_pacing.timer_expire = 1;
}

void
xqc_send_ctl_stream_close_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    xqc_msec_t min_expire = XQC_MAX_UINT64_VALUE;
    xqc_list_for_each_safe(pos, next, &conn->conn_closing_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, closing_stream_list);
        if (stream->stream_close_time <= now) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_type:%d|", stream->stream_id, stream->stream_type);
            xqc_list_del_init(pos);
            xqc_list_del_init(&stream->all_stream_list);
            xqc_destroy_stream(stream);
        } else {
            min_expire = xqc_min(min_expire, stream->stream_close_time);
        }
    }
    if (min_expire != XQC_MAX_UINT64_VALUE) {
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_STREAM_CLOSE, min_expire);
    }
}

void
xqc_send_ctl_ping_timeout(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t *) ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_PING;

    if (conn->conn_settings.ping_on && conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_PING, now + XQC_PING_TIMEOUT * 1000);
    }
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
        } else if (type == XQC_TIMER_PACING) {
            timer->ctl_timer_callback = xqc_send_ctl_pacing_timeout;
            timer->ctl_ctx = ctl;
        } else if (type == XQC_TIMER_STREAM_CLOSE) {
            timer->ctl_timer_callback = xqc_send_ctl_stream_close_timeout;
            timer->ctl_ctx = ctl;
        } else if (type == XQC_TIMER_PING) {
            timer->ctl_timer_callback = xqc_send_ctl_ping_timeout;
            timer->ctl_ctx = ctl;
        }
    }
}

/*
 * *****************TIMER END*****************
 */
