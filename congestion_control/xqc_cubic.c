
#include "xqc_cubic.h"
#include <math.h>

/* https://tools.ietf.org/html/rfc8312 */
#define XQC_MSS 1232
#define XQC_BETA_CUBIC 0.7f
#define XQC_C_CUBIC 0.4f

#define XQC_kMinWindow (4 * XQC_MSS)
#define XQC_kMaxWindow (100 * XQC_MSS)
#define XQC_kInitialWindow (32 * XQC_MSS)

#define xqc_max(a, b) ((a) > (b) ? (a) : (b))

static int fast_convergence = 1;

/*
 * Compute congestion window to use.
 * W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
 * K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
 * t为当前时间距上一次窗口减小的时间差
 * K代表该函数从W增长到Wmax的时间周期
 * C为窗口增长系数
 * beta为窗口降低系数
 */
static void
xqc_cubic_update(void *cong_ctl, uint32_t n_bytes, xqc_msec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    double offs; /* offs = |t - K| */
    /* delta = C*(t-K)^3 */
    uint32_t delta, bic_target;
    double t;

    // First ACK after a loss event.
    if (cubic->epoch_start == 0) {
        cubic->epoch_start = now;

        /* 取max(last_max_cwnd , cwnd)作为当前Wmax饱和点 */
        if (cubic->cwnd >= cubic->last_max_cwnd) {
            // 已经越过饱和点，使用当前窗口作为新的饱和点
            cubic->bic_K = 0;
            cubic->bic_origin_point = cubic->cwnd;
        } else {
            cubic->bic_K = cbrt((double)(cubic->last_max_cwnd - cubic->cwnd) / XQC_C_CUBIC / XQC_MSS);
            cubic->bic_origin_point = cubic->last_max_cwnd;
        }
    }

    t = (double)(now + cubic->min_rtt - cubic->epoch_start) / 1000000.f;

    /* 求| t - bic_K |  */
    if (t < cubic->bic_K) {
        offs = cubic->bic_K - t;
    } else {
        offs = t - cubic->bic_K;
    }

    delta = XQC_C_CUBIC * offs * offs * offs * XQC_MSS;

    if (t < cubic->bic_K) {
        bic_target = cubic->bic_origin_point - delta;
    } else {
        bic_target = cubic->bic_origin_point + delta;
    }

    if (cubic->tcp_cwnd > bic_target) {
        bic_target = cubic->tcp_cwnd;
    }

    if (bic_target == 0) {
        bic_target = cubic->init_cwnd;
    }

    cubic->cwnd = bic_target;
}

size_t
xqc_cubic_size ()
{
    return sizeof(xqc_cubic_t);
}

static void
xqc_cubic_init (void *cong_ctl, xqc_cc_params_t cc_params)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    if (cc_params.customize_on) {
        cc_params.init_cwnd *= XQC_MSS;
        cubic->init_cwnd =
                cc_params.init_cwnd >= XQC_kMinWindow && cc_params.init_cwnd <= XQC_kMaxWindow ?
                cc_params.init_cwnd : XQC_kInitialWindow;
    }

    cubic->epoch_start = 0;
    cubic->cwnd = cubic->init_cwnd;
    cubic->tcp_cwnd = cubic->init_cwnd;
    cubic->last_max_cwnd = cubic->init_cwnd;
    cubic->ssthresh = 0xFFFFFFFF;
}

/* https://tools.ietf.org/html/rfc8312#section-4.6
 * Fast Convergence & Multiplicative Decrease */
static void
xqc_cubic_on_lost (void *cong_ctl, xqc_msec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    cubic->epoch_start = 0;

    // should we make room for others
    if (fast_convergence && cubic->cwnd < cubic->last_max_cwnd){
        cubic->last_max_cwnd = cubic->cwnd;
        cubic->cwnd = cubic->cwnd * (1.0f + XQC_BETA_CUBIC) / 2.0f;
    } else {
        cubic->last_max_cwnd = cubic->cwnd;
    }

    //Multiplicative Decrease
    cubic->cwnd *= XQC_BETA_CUBIC;
    cubic->tcp_cwnd = cubic->cwnd;
    //threshold is at least XQC_kMinWindow
    cubic->ssthresh = xqc_max(cubic->cwnd, XQC_kMinWindow);
}

static void
xqc_cubic_on_ack (void *cong_ctl, xqc_msec_t sent_time, xqc_msec_t now, uint32_t n_bytes)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    xqc_msec_t rtt = now - sent_time;

    if (cubic->min_rtt == 0 || rtt < cubic->min_rtt) {
        cubic->min_rtt = rtt;
    }

    if (cubic->cwnd < cubic->ssthresh) {
        //slow start
        cubic->tcp_cwnd += XQC_MSS;
        cubic->cwnd += XQC_MSS;
    } else {
        //congestion avoidance
        cubic->tcp_cwnd += XQC_MSS * n_bytes / cubic->tcp_cwnd;
        xqc_cubic_update(cong_ctl, n_bytes, sent_time);
    }
}

uint32_t
xqc_cubic_get_cwnd (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    return cubic->cwnd;
}

void
xqc_cubic_reset_cwnd (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = cubic->init_cwnd;
    cubic->tcp_cwnd = cubic->init_cwnd;
    cubic->last_max_cwnd = cubic->init_cwnd;
}

int32_t
xqc_cubic_in_slow_start (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    return cubic->cwnd < cubic->ssthresh ? 1 : 0;
}

const xqc_cong_ctrl_callback_t xqc_cubic_cb = {
        .xqc_cong_ctl_size      = xqc_cubic_size,
        .xqc_cong_ctl_init      = xqc_cubic_init,
        .xqc_cong_ctl_on_lost   = xqc_cubic_on_lost,
        .xqc_cong_ctl_on_ack    = xqc_cubic_on_ack,
        .xqc_cong_ctl_get_cwnd  = xqc_cubic_get_cwnd,
        .xqc_cong_ctl_reset_cwnd = xqc_cubic_reset_cwnd,
        .xqc_cong_ctl_in_slow_start = xqc_cubic_in_slow_start,
};