#include "xqc_sample.h"


bool xqc_generate_sample(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl)
{

    if(sampler->prior_time == 0)
        return false;
    sampler->interval = max(sampler->ack_elapse, sampler->send_elapse);
    sampler->delivered = send_ctl->ctl_delivered - sampler->prior_delivered;
    if (sampler->interval < send_ctl->ctl_minrtt){
        sampler->interval = -1;
        return false;
    } 
    if(sampler->interval != 0)
        sampler->delivery_rate = sampler->dilivered / sampler->interval;
    
    sampler->now = xqc_now();
    sampler->rtt = send_ctl->ctl_latest_rtt;
    sampler->srtt = send_ctl->ctl_srtt;
    sampler->bytes_inflight = send_ctl->ctl_bytes_in_flight;
    sampler->total_acked = send_ctl->ctl_delivered;
    return true;
}

void xqc_update_sample(xqc_sample_t *sampler, xqc_packet_out_t *packet, xqc_send_ctl_t *send_ctl)
{
    if(packet->po_delivered_time == 0)
        return;
    
    send_ctl->ctl_delivered += packet->po_used_size;
    sned_ctl->ctl_delivered_time = xqc_now();

    if(packet->po_delivered > sampler->prior_dilivered){
        sampler->prior_dilivered = packet->po_delivered;
        sampler->prior_time = packet->po_delivered_time;
        sampler->sned_elapse = packet->po_sent_time - packet->po_first_sent_time;
        sampler->ack_time = send_ctl->ctl_delivered_time - packet->po_delivered_time;
        send_ctl->ctl_first_sent_time = packet->po_sent_time;
    }

    packet->po_delivered_time = 0;
}