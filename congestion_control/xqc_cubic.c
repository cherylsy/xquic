
#include "xqc_cubic.h"
#include <math.h>

/* https://tools.ietf.org/html/rfc8312 */

#define XQC_FAST_CONVERGENCE 1
#define XQC_MSS 1232
#define XQC_BETA_CUBIC 718 // 718/1024=0.7 浮点运算性能差，避免浮点运算
#define XQC_BETA_CUBIC_SCALE 1024
#define XQC_C_CUBIC 410 // 410/1024=0.4
#define XQC_CUBE_SCALE 40 //2^40=1024 * 1024^3
#define XQC_MICROS_PER_SECOND 1000000 //1s=1000000us

#define XQC_kMinWindow (4 * XQC_MSS)
#define XQC_kMaxWindow (100 * XQC_MSS)
#define XQC_kInitialWindow (32 * XQC_MSS)

#define xqc_max(a, b) ((a) > (b) ? (a) : (b))
#define xqc_min(a, b) ((a) < (b) ? (a) : (b))

const static uint64_t cube_factor =
        (1ull << XQC_CUBE_SCALE) / XQC_C_CUBIC / XQC_MSS;

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
xqc_cubic_update(void *cong_ctl, uint32_t acked_bytes, xqc_msec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    uint64_t t; //ms
    uint64_t offs; // offs = |t - K|
    // delta = C*(t-K)^3
    uint64_t delta, bic_target;

    // First ACK after a loss event.
    if (cubic->epoch_start == 0) {
        cubic->epoch_start = now;

        /* 取max(last_max_cwnd , cwnd)作为当前Wmax饱和点 */
        if (cubic->cwnd >= cubic->last_max_cwnd) {
            // 已经越过饱和点，使用当前窗口作为新的饱和点
            cubic->bic_K = 0;
            cubic->bic_origin_point = cubic->cwnd;
        } else {
            /* K = cubic_root(W_max*(1-beta_cubic)/C) = cubic_root((W_max-cwnd)/C)
             * cube_factor = (1ull << XQC_CUBE_SCALE) / XQC_C_CUBIC / XQC_MSS
             *             = 2^40 / (410 * MSS) = 2^30 / (410/1024*MSS)
             *             = 2^30 / (C*MSS)
             */
            cubic->bic_K = cbrt(cube_factor * (cubic->last_max_cwnd - cubic->cwnd));
            cubic->bic_origin_point = cubic->last_max_cwnd;
        }
    }

    // t = elapsed_time * 1024 / 1000000 微秒转换为毫秒，乘1024为了后面能用位操作
    t = (now + cubic->min_rtt - cubic->epoch_start) << 10 / XQC_MICROS_PER_SECOND;

    // 求|t - K|
    if (t < cubic->bic_K) {
        offs = cubic->bic_K - t;
    } else {
        offs = t - cubic->bic_K;
    }

    // delta = 410/1024 * off/1024 * off/1024 * off/1024 * MSS
    delta = (XQC_C_CUBIC * offs * offs * offs * XQC_MSS) >> XQC_CUBE_SCALE;

    if (t < cubic->bic_K) {
        bic_target = cubic->bic_origin_point - delta;
    } else {
        bic_target = cubic->bic_origin_point + delta;
    }

    /* CUBIC最大增长速率为1.5x per RTT. 即每2个ack增加1个窗口
	 */
    bic_target = xqc_min(bic_target, cubic->cwnd + acked_bytes / 2);

    // 取TCP reno的cwnd 和 cubic的cwnd 的最大值
    bic_target = xqc_max(cubic->tcp_cwnd, bic_target);

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
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_kInitialWindow;
    cubic->tcp_cwnd = XQC_kInitialWindow;
    cubic->last_max_cwnd = XQC_kInitialWindow;
    cubic->ssthresh = 0xFFFFFFFF;

    if (cc_params.customize_on) {
        cc_params.init_cwnd *= XQC_MSS;
        cubic->init_cwnd =
                cc_params.init_cwnd >= XQC_kMinWindow && cc_params.init_cwnd <= XQC_kMaxWindow ?
                cc_params.init_cwnd : XQC_kInitialWindow;
    }
}

/* https://tools.ietf.org/html/rfc8312#section-4.6
 * Fast Convergence & Multiplicative Decrease */
static void
xqc_cubic_on_lost (void *cong_ctl, xqc_msec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    cubic->epoch_start = 0;

    // should we make room for others
    if (XQC_FAST_CONVERGENCE && cubic->cwnd < cubic->last_max_cwnd){
        cubic->last_max_cwnd = cubic->cwnd;
        //cubic->cwnd = cubic->cwnd * (1.0f + XQC_BETA_CUBIC) / 2.0f
        cubic->cwnd = cubic->cwnd * (XQC_BETA_CUBIC_SCALE + XQC_BETA_CUBIC) / 2 / XQC_BETA_CUBIC_SCALE;
    } else {
        cubic->last_max_cwnd = cubic->cwnd;
    }

    //Multiplicative Decrease
    cubic->cwnd = cubic->cwnd * XQC_BETA_CUBIC / XQC_BETA_CUBIC_SCALE;
    cubic->tcp_cwnd = cubic->cwnd;
    //threshold is at least XQC_kMinWindow
    cubic->ssthresh = xqc_max(cubic->cwnd, XQC_kMinWindow);
}

static void
xqc_cubic_on_ack (void *cong_ctl, xqc_msec_t sent_time, xqc_msec_t now, uint32_t acked_bytes)
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
        cubic->tcp_cwnd += XQC_MSS * acked_bytes / cubic->tcp_cwnd;
        xqc_cubic_update(cong_ctl, acked_bytes, now);
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