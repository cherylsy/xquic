#include "xqc_pacing.h"
#include "xqc_send_ctl.h"

#define XQC_MAX_BURST_NUM 2

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on, xqc_send_ctl_t *ctl)
{
    pacing->burst_num = 0;
    pacing->next_send_time = 0;
    pacing->timer_expire = 0;
    pacing->on = pacing_on;
    if (ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
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
    if (ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        pacing_rate = ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong);
        //xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|zzl-cwnd == pacing: %ui|", pacing_rate);
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
    if (ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        bw_estimate = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
        return bw_estimate;
    }

    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);

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
                               xqc_connection_t *conn, xqc_packet_out_t *packet_out) {

    if (pacing->burst_tokens > 0) {
        --pacing->burst_tokens;
        // TODO: next_send_time reset ?
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
        pacing->lumpy_tokens = xqc_max(1,
                                       xqc_min(2, ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong) * 0.25 / 1200));

        /*
         * bandwidth estimate
         * bbr => bandwidth
         * cubic => cwnd / srtt
         */
        uint64_t bandwidth_estimate = xqc_pacing_bw_estimate_calc(pacing, ctl);
        uint64_t smallest_bandwidth = 1.2 * 1000000 / 8;  // a smallest bandwidth
        if (bandwidth_estimate < smallest_bandwidth) {
            pacing->lumpy_tokens = 1;
        }
    }

    --pacing->lumpy_tokens;

    if (pacing->pacing_limited) {
        pacing->ideal_next_packet_send_time = pacing->ideal_next_packet_send_time + delay;
    } else {
        pacing->ideal_next_packet_send_time = xqc_max(pacing->ideal_next_packet_send_time + delay, xqc_now() + delay);
    }

    /*
     * Check can_send
     * bbr: bytes_in_flight + bytes < cwnd
     * cubic: not same, but
     */

    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    if (ctl->ctl_bytes_in_flight + packet_out->po_used_size < cwnd) {
        pacing->pacing_limited = 1;
    } else {
        pacing->pacing_limited = 0;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|delay:%ud|delta:%i|pacing_limited:%d|pacing_rate:%ui|burst_tokens:%ud|lumpy_tokens:%ud|",
            delay, (int64_t)pacing->ideal_next_packet_send_time - xqc_now(), pacing->pacing_limited, pacing_rate,
            ctl->ctl_pacing.burst_tokens, ctl->ctl_pacing.lumpy_tokens);
}

uint64_t xqc_pacing_time_until_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
                                    xqc_connection_t *conn, xqc_packet_out_t *packet_out) {

    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    if (ctl->ctl_bytes_in_flight >= cwnd) {
        return INFINITE_TIME;
    }

    if (pacing->burst_tokens > 0 || ctl->ctl_bytes_in_flight == 0 || pacing->lumpy_tokens > 0) {
        return 0;
    }

    uint64_t time_now = xqc_now();
    if (pacing->ideal_next_packet_send_time > time_now + 1000) {
        return pacing->ideal_next_packet_send_time - time_now;
    }
    //xqc_log(conn->log, XQC_LOG_DEBUG,"|ideal_next_packet_send_time:%ui|", pacing->ideal_next_packet_send_time);
    return 0;
}

int xqc_pacing_can_write(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
                         xqc_connection_t *conn, xqc_packet_out_t *packet_out) {

//     uint64_t smallest_bandwidth = 1.2 * 1000000 / 8;
    uint64_t pacing_rate = xqc_pacing_rate_calc(pacing, ctl);

//    if (pacing_rate < smallest_bandwidth)
//        return true;

    if (ctl->ctl_bytes_in_flight == 0) {
        pacing->burst_tokens = XQC_MAX_BURST_NUM;
    }

    // check timer
    if (xqc_send_pacing_timer_isset(ctl, XQC_TIMER_PACING)) {
        return false;
    }

    uint64_t delay = xqc_pacing_time_until_send(pacing, ctl, conn, packet_out);

    // check it is infinit
    if (delay == INFINITE_TIME) {
        return false;
    }

    if (delay != 0) {
        // update timer
        xqc_send_pacing_timer_update(ctl, XQC_TIMER_PACING, xqc_now() + delay);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|PACING timer update|delay:%ui|", delay);
        return false;
    }

    return true;

}