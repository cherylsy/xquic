#include "xqc_sample.h"
#include "common/xqc_config.h"
#include "transport/xqc_send_ctl.h"
#include "transport/xqc_packet_out.h"

/**
 * see https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-00#section-3.3
 */
/* Upon receiving ACK, fill in delivery rate sample rs. */
bool xqc_generate_sample(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl, xqc_msec_t now)
{
    /* Clear app-limited field if bubble is ACKed and gone. */
    if (send_ctl->ctl_app_limited && send_ctl->ctl_delivered > send_ctl->ctl_app_limited) {
        send_ctl->ctl_app_limited = 0;
    }

    if(sampler->prior_time == 0) {
        //printf("bbr=================== xqc_generate_sample false sampler->prior_time == 0\n");
        return false; /* nothing delivered on this ACK */
    }

    /* Use the longer of the send_elapsed and ack_elapsed */
    sampler->interval = xqc_max(sampler->ack_elapse, sampler->send_elapse);

    sampler->delivered = send_ctl->ctl_delivered - sampler->prior_delivered;

    /* Normally we expect interval >= MinRTT.
        * Note that rate may still be over-estimated when a spuriously
        * retransmitted skb was first (s)acked because "interval"
        * is under-estimated (up to an RTT). However, continuously
        * measuring the delivery rate during loss recovery is crucial
        * for connections suffer heavy or prolonged losses.
        */
    if (sampler->interval < send_ctl->ctl_minrtt){
        sampler->interval = 0;
        //printf("bbr==================== xqc_generate_sample false sampler->interval < send_ctl->ctl_minrtt\n");
        return false;
    }
    if(sampler->interval != 0) {
        sampler->delivery_rate = sampler->delivered / sampler->interval;
    }
    sampler->now = now;
    sampler->rtt = send_ctl->ctl_latest_rtt;
    sampler->srtt = send_ctl->ctl_srtt;
    sampler->bytes_inflight = send_ctl->ctl_bytes_in_flight;
    sampler->prior_inflight = send_ctl->ctl_prior_bytes_in_flight;
    sampler->total_acked = send_ctl->ctl_delivered;
    return true;
}

/* Update rs when packet is SACKed or ACKed. */
void xqc_update_sample(xqc_sample_t *sampler, xqc_packet_out_t *packet, xqc_send_ctl_t *send_ctl, xqc_msec_t now)
{
    if(packet->po_delivered_time == 0) {
        printf("bbr======update sample failed\n");
        return; /* P already SACKed */
    }
    send_ctl->ctl_delivered += packet->po_used_size;
    //printf("bbr++++++++++xqc_update_sample ctl_delivered %llu\n",send_ctl->ctl_delivered);
    send_ctl->ctl_delivered_time = now;

    /* Update info using the newest packet: */
    if(packet->po_delivered > sampler->prior_delivered){
        sampler->prior_delivered = packet->po_delivered;
        sampler->prior_time = packet->po_delivered_time;
        sampler->is_app_limited = packet->po_is_app_limited;
        sampler->send_elapse = packet->po_sent_time - packet->po_first_sent_time;
        sampler->ack_elapse = send_ctl->ctl_delivered_time - packet->po_delivered_time;
        send_ctl->ctl_first_sent_time = packet->po_sent_time;

        sampler->lagest_ack_time = now;

    }

    /* Mark the packet as delivered once it's SACKed to
    * avoid being used again when it's cumulatively acked.
    */
    packet->po_delivered_time = 0;
}

void xqc_sample_check_app_limited(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl)
{
    if (/* We are not limited by CWND. */
        send_ctl->ctl_bytes_in_flight <
        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong) &&
        /* We have no packet to send. */
        xqc_list_empty(&send_ctl->ctl_send_packets) &&
        /* All lost packets have been retransmitted. */
        xqc_list_empty(&send_ctl->ctl_lost_packets)) {
        send_ctl->ctl_app_limited = send_ctl->ctl_delivered + send_ctl->ctl_bytes_in_flight ? : 1;
        //xqc_log(send_ctl->ctl_conn->log, XQC_LOG_INFO, "|bbr on ack|ctl_bytes_in_flight:%ud|send empty:%ud|lost empty:%ud|",
        //        send_ctl->ctl_bytes_in_flight, xqc_list_empty(&send_ctl->ctl_send_packets)?1:0, xqc_list_empty(&send_ctl->ctl_lost_packets)?1:0);
    }
}

void xqc_sample_on_sent(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl, xqc_msec_t now)
{
    if (ctl->ctl_bytes_in_flight == 0) {
        ctl->ctl_delivered_time = ctl->ctl_first_sent_time = now;
    }
    packet_out->po_delivered_time = ctl->ctl_delivered_time;
    packet_out->po_first_sent_time = ctl->ctl_first_sent_time;
    packet_out->po_delivered = ctl->ctl_delivered;
    packet_out->po_is_app_limited = ctl->ctl_app_limited > 0 ? 1 : 0;
}