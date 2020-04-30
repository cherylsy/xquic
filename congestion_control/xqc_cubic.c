
#include "xqc_cubic.h"
#include <math.h>

/* https://tools.ietf.org/html/rfc8312 */
#define XQC_MSS 1460
#define XQC_BETA_CUBIC 0.7f
#define XQC_C_CUBIC 0.4f

#define XQC_kMinimumWindow (4 * XQC_MSS)
#define XQC_kInitialWindow (32 * XQC_MSS)

#define xqc_max(a, b) ((a) > (b) ? (a) : (b))

static int fast_convergence = 1;

/*
 * Compute congestion window to use.
 * W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
 * K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
 */
static void
xqc_cubic_update(void *cong_ctl, unsigned n_bytes, xqc_msec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    double offs; /* |t - K| */
    /* delta是C*(t-K)^3，bic_target是预测值，t为预测时间 */
    uint64_t delta, bic_target;
    double t;

    if (cubic->epoch_start == 0) {
        cubic->epoch_start = now;

        /* 取max(last_max_cwnd , cwnd)作为当前Wmax饱和点 */
        if (cubic->last_max_cwnd <= cubic->cwnd) {
            /* cwnd已经增长到bic_origin_point，K=0 */
            cubic->bic_K = 0;
            cubic->bic_origin_point = cubic->cwnd;
        } else {
            cubic->bic_K = cbrt((double)cubic->last_max_cwnd / XQC_MSS * (1.0f - XQC_BETA_CUBIC) / XQC_C_CUBIC);
            cubic->bic_origin_point = cubic->last_max_cwnd;
        }
    }

    t = (double)(now - cubic->epoch_start) / 1000000.f;

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
        bic_target = XQC_kInitialWindow;
    }

    cubic->cwnd = bic_target;
}

size_t
xqc_cubic_size ()
{
    return sizeof(xqc_cubic_t);
}

static void
xqc_cubic_init (void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_kInitialWindow;
    cubic->tcp_cwnd = XQC_kInitialWindow;
    cubic->last_max_cwnd = XQC_kInitialWindow;
    cubic->ssthresh = 0xffffffff;
}


static void
xqc_cubic_on_lost (void *cong_ctl, xqc_msec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    cubic->epoch_start = 0;

    if (fast_convergence && cubic->cwnd < cubic->last_max_cwnd){
        cubic->last_max_cwnd = cubic->cwnd;
        cubic->cwnd = cubic->cwnd * (1.0f + XQC_BETA_CUBIC) / 2.0f;
    } else {
        cubic->last_max_cwnd = cubic->cwnd;
    }

    //in_recovery?
    cubic->cwnd *= XQC_BETA_CUBIC;
    cubic->tcp_cwnd *= XQC_BETA_CUBIC;
    cubic->ssthresh = xqc_max(cubic->cwnd, XQC_kMinimumWindow);
}

static void
xqc_cubic_on_ack (void *cong_ctl, xqc_msec_t sent_time, uint32_t n_bytes)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    if (cubic->cwnd < cubic->ssthresh) {
        cubic->cwnd += XQC_MSS;
        cubic->tcp_cwnd += XQC_MSS;
    } else {
        cubic->tcp_cwnd += XQC_MSS * n_bytes / cubic->tcp_cwnd;
        //APP limit?
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
    cubic->cwnd = XQC_kInitialWindow;
    cubic->tcp_cwnd = XQC_kInitialWindow;
    cubic->last_max_cwnd = XQC_kInitialWindow;
}

int
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