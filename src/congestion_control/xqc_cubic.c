/*
 * CUBIC based on https://tools.ietf.org/html/rfc8312
 */

#include "src/congestion_control/xqc_cubic.h"
#include "src/common/xqc_config.h"
#include <math.h>

#define XQC_CUBIC_FAST_CONVERGENCE  1
#define XQC_CUBIC_MSS               1460
#define XQC_CUBIC_BETA              718     // 718/1024=0.7 浮点运算性能差，避免浮点运算
#define XQC_CUBIC_BETA_SCALE        1024
#define XQC_CUBIC_C                 410     // 410/1024=0.4
#define XQC_CUBE_SCALE              40u     // 2^40=1024 * 1024^3
#define XQC_CUBIC_TIME_SCALE        10u
#define XQC_CUBIC_MAX_SSTHRESH      0xFFFFFFFF

#define XQC_CUBIC_MIN_WIN           (4 * XQC_CUBIC_MSS)
#define XQC_CUBIC_MAX_INIT_WIN      (100 * XQC_CUBIC_MSS)
#define XQC_CUBIC_INIT_WIN          (32 * XQC_CUBIC_MSS)

const static uint64_t xqc_cube_factor =
        (1ull << XQC_CUBE_SCALE) / XQC_CUBIC_C / XQC_CUBIC_MSS;

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
    uint64_t t; //单位ms
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
             * cube_factor = (1ull << XQC_CUBE_SCALE) / XQC_CUBIC_C / XQC_MSS
             *             = 2^40 / (410 * MSS) = 2^30 / (410/1024*MSS)
             *             = 2^30 / (C*MSS)
             */
            cubic->bic_K = cbrt(xqc_cube_factor * (cubic->last_max_cwnd - cubic->cwnd));
            cubic->bic_origin_point = cubic->last_max_cwnd;
        }
    }

    // t = elapsed_time * 1024 / 1000000 微秒转换为毫秒，乘1024为了后面能用位操作
    t = (now + cubic->min_rtt - cubic->epoch_start) << XQC_CUBIC_TIME_SCALE / XQC_MICROS_PER_SECOND;

    // 求|t - K|
    if (t < cubic->bic_K) {
        offs = cubic->bic_K - t;
    } else {
        offs = t - cubic->bic_K;
    }

    // 410/1024 * off/1024 * off/1024 * off/1024 * MSS
    delta = (XQC_CUBIC_C * offs * offs * offs * XQC_CUBIC_MSS) >> XQC_CUBE_SCALE;

    if (t < cubic->bic_K) {
        bic_target = cubic->bic_origin_point - delta;
    } else {
        bic_target = cubic->bic_origin_point + delta;
    }

    // CUBIC最大增长速率为1.5x per RTT. 即每2个ack增加1个窗口
    bic_target = xqc_min(bic_target, cubic->cwnd + acked_bytes / 2);

    // 取TCP reno的cwnd 和 cubic的cwnd 的最大值
    bic_target = xqc_max(cubic->tcp_cwnd, bic_target);

    if (bic_target == 0) {
        bic_target = cubic->init_cwnd;
    }

    cubic->cwnd = bic_target;
}

/*
 * 返回拥塞算法结构体大小
 */
size_t
xqc_cubic_size ()
{
    return sizeof(xqc_cubic_t);
}

/*
 * 拥塞算法初始化
 */
static void
xqc_cubic_init (void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_CUBIC_INIT_WIN;
    cubic->tcp_cwnd = XQC_CUBIC_INIT_WIN;
    cubic->last_max_cwnd = XQC_CUBIC_INIT_WIN;
    cubic->ssthresh = XQC_CUBIC_MAX_SSTHRESH;

    if (cc_params.customize_on) {
        cc_params.init_cwnd *= XQC_CUBIC_MSS;
        cubic->init_cwnd =
                cc_params.init_cwnd >= XQC_CUBIC_MIN_WIN && cc_params.init_cwnd <= XQC_CUBIC_MAX_INIT_WIN ?
                cc_params.init_cwnd : XQC_CUBIC_INIT_WIN;
    }
}

/*
 * Decrease CWND when lost detected
 */
static void
xqc_cubic_on_lost (void *cong_ctl, xqc_msec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    cubic->epoch_start = 0;

    // should we make room for others
    if (XQC_CUBIC_FAST_CONVERGENCE && cubic->cwnd < cubic->last_max_cwnd){
        // (1.0f + XQC_CUBIC_BETA) / 2.0f 转换为位运算
        cubic->last_max_cwnd = cubic->cwnd * (XQC_CUBIC_BETA_SCALE + XQC_CUBIC_BETA) / (2 * XQC_CUBIC_BETA_SCALE);
    } else {
        cubic->last_max_cwnd = cubic->cwnd;
    }

    // Multiplicative Decrease
    cubic->cwnd = cubic->cwnd * XQC_CUBIC_BETA / XQC_CUBIC_BETA_SCALE;
    cubic->tcp_cwnd = cubic->cwnd;
    // threshold is at least XQC_CUBIC_MIN_WIN
    cubic->ssthresh = xqc_max(cubic->cwnd, XQC_CUBIC_MIN_WIN);
}

/*
 * Increase CWND when packet acked
 */
static void
xqc_cubic_on_ack (void *cong_ctl, xqc_packet_out_t *po, xqc_msec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    xqc_msec_t  sent_time = po->po_sent_time;
    uint32_t    acked_bytes = po->po_used_size;

    xqc_msec_t rtt = now - sent_time;

    if (cubic->min_rtt == 0 || rtt < cubic->min_rtt) {
        cubic->min_rtt = rtt;
    }

    if (cubic->cwnd < cubic->ssthresh) {
        // slow start
        cubic->tcp_cwnd += acked_bytes;
        cubic->cwnd += acked_bytes;
    } else {
        // congestion avoidance
        cubic->tcp_cwnd += XQC_CUBIC_MSS * XQC_CUBIC_MSS / cubic->tcp_cwnd;
        xqc_cubic_update(cong_ctl, acked_bytes, now);
    }
}

/*
 * 返回拥塞窗口
 */
uint64_t
xqc_cubic_get_cwnd (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    return cubic->cwnd;
}

/*
 * 检测到一个RTT内所有包都丢失时回调，重置拥塞窗口
 */
void
xqc_cubic_reset_cwnd (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_CUBIC_MIN_WIN;
    cubic->tcp_cwnd = XQC_CUBIC_MIN_WIN;
    cubic->last_max_cwnd = XQC_CUBIC_MIN_WIN;
}

/*
 * 是否处于慢启动阶段
 */
int32_t
xqc_cubic_in_slow_start (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    return cubic->cwnd < cubic->ssthresh ? 1 : 0;
}

void
xqc_cubic_restart_from_idle(void *cong_ctl, uint64_t arg) {
    return;
}

const xqc_cong_ctrl_callback_t xqc_cubic_cb = {
        .xqc_cong_ctl_size              = xqc_cubic_size,
        .xqc_cong_ctl_init              = xqc_cubic_init,
        .xqc_cong_ctl_on_lost           = xqc_cubic_on_lost,
        .xqc_cong_ctl_on_ack            = xqc_cubic_on_ack,
        .xqc_cong_ctl_get_cwnd          = xqc_cubic_get_cwnd,
        .xqc_cong_ctl_reset_cwnd        = xqc_cubic_reset_cwnd,
        .xqc_cong_ctl_in_slow_start     = xqc_cubic_in_slow_start,
        .xqc_cong_ctl_restart_from_idle = xqc_cubic_restart_from_idle,
};