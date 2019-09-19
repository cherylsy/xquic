
#include "xqc_pacing.h"
#include "xqc_send_ctl.h"

#define XQC_MAX_BURST_NUM 1

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on)
{
    pacing->burst_num = 0;
    pacing->next_send_time = 0;
    pacing->timer_expire = 0;
    pacing->on = pacing_on;
}

/**
 * @return 是否启用pacing
 */
int
xqc_pacing_is_on(xqc_pacing_t *pacing)
{
    return pacing->on;
}

/**
 * @return 每秒可发字节数
 */
uint64_t
xqc_pacing_rate_calc(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    /* see linux kernel tcp_update_pacing_rate(struct sock *sk) */
    uint64_t pacing_rate;
    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);

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

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|cwnd:%ui|srtt:%ui|pacing_rate:%ui|", cwnd, srtt, pacing_rate);

    return pacing_rate;
}

/**
 * @return 一个包占用的时间片
 */
xqc_msec_t
xqc_pacing_time_cost(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    return XQC_MSS * 1000000 / xqc_pacing_rate_calc(pacing, ctl);
}

/**
 * 此次不能发送则更新可发送时间
 */
void
xqc_pacing_schedule(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_bytes_in_flight == 0) {
        pacing->burst_num = 0;
    }

    /* 上次更新过，此次不更新时间 */
    if (pacing->timer_expire == 1) {
        pacing->timer_expire = 0;
        ++pacing->burst_num;
        return;
    }

    if (pacing->burst_num < XQC_MAX_BURST_NUM) {
        ++pacing->burst_num;
    } else {
        ++pacing->burst_num;
        //pacing->burst_num = XQC_MAX_BURST_NUM + 1;
        pacing->next_send_time = xqc_now() + xqc_pacing_time_cost(pacing, ctl) * (pacing->burst_num - 1);
    }
}

int
xqc_pacing_can_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl)
{
    xqc_msec_t now = xqc_now();
    int can = 0;
    if (pacing->burst_num <= XQC_MAX_BURST_NUM) {
        can = 1;
    }

    if (pacing->next_send_time <= now) {
        can = 1;
    }

    /* 定时器精度只有1ms */
    if (pacing->next_send_time - now < 1000) {
        can = 1;
    }

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_pacing_can_send|%ui", can);
    return can;
}