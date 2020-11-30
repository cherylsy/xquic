#include "src/transport/xqc_pacing.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet.h"

#define XQC_MAX_BURST_NUM 10
#define TRUE 1
#define FALSE 0
#define XQC_CLOCK_GRANULARITY_US 1000 /*1ms*/

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on, xqc_send_ctl_t *ctl)
{
    pacing->initial_burst_size = XQC_MAX_BURST_NUM;
    pacing->burst_tokens = XQC_MAX_BURST_NUM;
    pacing->ideal_next_packet_send_time = 0;
    pacing->on = pacing_on;
    pacing->lumpy_tokens = 0;
    pacing->alarm_granularity = XQC_CLOCK_GRANULARITY_US;
    if (ctl->ctl_cong_callback->xqc_cong_ctl_bbr) {
        pacing->on = 1;
    }
}

/**
 * @return 每秒可发字节数
 */
uint64_t
xqc_pacing_rate_calc(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    /* see linux kernel tcp_update_pacing_rate(struct sock *sk) */
    uint64_t pacing_rate;
    uint64_t cwnd;
    if (ctl->ctl_cong_callback->xqc_cong_ctl_bbr) {
        pacing_rate = ctl->ctl_cong_callback->
                      xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong);
        return pacing_rate;
    }

    cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);

    xqc_msec_t srtt = ctl->ctl_srtt;
    if (srtt == 0) {
        srtt = XQC_kInitialRtt * 1000;
    }

    /* 每秒可发字节数 */
    pacing_rate = cwnd * 1000000 / srtt;

    if (ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start &&
        ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(ctl->ctl_cong)) {
        pacing_rate *= 2;

    } else {
        pacing_rate = pacing_rate * 12 / 10;
    }

    return pacing_rate;
}

/*
 * bandwidth estimate
 */
static uint64_t
xqc_pacing_bw_estimate_calc(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    uint64_t bw_estimate;
    if (ctl->ctl_cong_callback->xqc_cong_ctl_bbr) {
        bw_estimate = ctl->ctl_cong_callback->
                      xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
        return bw_estimate;
    }

    uint64_t cwnd = ctl->ctl_cong_callback->
                    xqc_cong_ctl_get_cwnd(ctl->ctl_cong);

    xqc_msec_t srtt = ctl->ctl_srtt;
    if (srtt == 0) {
        srtt = XQC_kInitialRtt * 1000;
    }

    bw_estimate = cwnd * 1000000 / srtt ;

    return bw_estimate;
}

/*
 * token consuming from chrome-quic
 */
void xqc_pacing_on_packet_sent(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint32_t inflight)
{

    if (inflight == 0 
        && !ctl->ctl_cong_callback->xqc_cong_ctl_in_recovery(ctl->ctl_cong))
    {
        pacing->burst_tokens = pacing->initial_burst_size;
    }

    if (pacing->burst_tokens > 0) {
        --pacing->burst_tokens;
        pacing->pacing_limited = 0;
        return;
    }

    /*
     * bytes_inflight_to_bandwidth
     * bbr => return pacing_rate
     * cubic => return cwnd / srtt * 2 or * 1.25
     */
    uint64_t pacing_rate = xqc_pacing_rate_calc(pacing, ctl);
    uint32_t delay = packet_out->po_used_size * 1000000 / pacing_rate;

    if (!pacing->pacing_limited || pacing->lumpy_tokens == 0) {
        uint64_t cwnd = ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
        pacing->lumpy_tokens = xqc_max(1, xqc_min(2,  cwnd * 0.25 / XQC_QUIC_MSS));

        /*
         * bandwidth estimate
         * bbr => bandwidth
         * cubic => cwnd / srtt
         */
        uint64_t bandwidth_estimate = xqc_pacing_bw_estimate_calc(pacing, ctl);
        uint64_t smallest_bandwidth = 1.2 * 1000000 / 8;
        if (bandwidth_estimate < smallest_bandwidth) {
            pacing->lumpy_tokens = 1;
        }
    }

    --pacing->lumpy_tokens;

    uint64_t now = xqc_now();

    if (pacing->pacing_limited) {
        pacing->ideal_next_packet_send_time += delay;
        
    } else {
        uint64_t _tmp = pacing->ideal_next_packet_send_time + delay;
        pacing->ideal_next_packet_send_time = xqc_max(_tmp, now + delay);
    }

    /*
     * Check can_send
     * bbr: bytes_in_flight + bytes < cwnd
     * cubic: not same, but
     */

    uint64_t cwnd = ctl->ctl_cong_callback->
                    xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    if (inflight + packet_out->po_used_size < cwnd) {
        /* This does not neccessarily mean we are limited by pacing, if 
           there is only a bit space in cwnd. So, we will also call 
           xqc_pacing_on_cwnd_limit() to clear pacing_limited if needed. */
        pacing->pacing_limited = 1;
    } else {
        pacing->pacing_limited = 0;
    }

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|delay:%ud|next_sending_time:%ui|pacing_limited:%d|"
            "pacing_rate:%ui|burst_tokens:%ud|lumpy_tokens:%ud|", 
            delay, pacing->ideal_next_packet_send_time, 
            pacing->pacing_limited, pacing_rate,
            ctl->ctl_pacing.burst_tokens, ctl->ctl_pacing.lumpy_tokens);
}

uint64_t xqc_pacing_time_until_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint32_t inflight)
{

    if (pacing->burst_tokens > 0 
        || inflight == 0 
        || pacing->lumpy_tokens > 0) 
    {
        return 0;
    }

    uint64_t time_now = xqc_now();
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|ideal_next_packet_send_time:%ui|now: %ui|", 
            pacing->ideal_next_packet_send_time, time_now);
    if (pacing->ideal_next_packet_send_time 
        > (time_now + pacing->alarm_granularity))
    {
        return pacing->ideal_next_packet_send_time - time_now;
    }
    return 0;
}

int xqc_pacing_can_write(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint32_t inflight)
{

    if (xqc_send_pacing_timer_isset(ctl, XQC_TIMER_PACING)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|waiting for pacing timer to expire!|");
        return FALSE;
    }

    uint64_t delay = xqc_pacing_time_until_send(pacing, ctl, conn, packet_out, inflight);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|pacing_delay: %ud!", delay);

    if (delay != 0) {
        xqc_send_pacing_timer_update(ctl, XQC_TIMER_PACING, xqc_now() + delay);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|PACING timer update|delay:%ui|", 
                delay);
        return FALSE;
    }

    return TRUE;

}

void xqc_pacing_on_cwnd_limit(xqc_pacing_t *pacing) {
    pacing->pacing_limited = 0;
}

void xqc_pacing_on_loss_event(xqc_pacing_t *pacing) {
    pacing->burst_tokens = 0;
}

void xqc_pacing_on_app_limit(xqc_pacing_t *pacing) {
    pacing->pacing_limited = 0;
}