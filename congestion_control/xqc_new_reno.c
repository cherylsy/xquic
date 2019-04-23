
#include <sys/time.h>
#include "xqc_new_reno.h"
#include "../include/xquic.h"

#define XQC_kMaxDatagramSize 1200
#define XQC_kMinimumWindow (2 * XQC_kMaxDatagramSize)
/*The RECOMMENDED value is the minimum of 10 *
kMaxDatagramSize and max(2* kMaxDatagramSize, 14720)).*/
#define XQC_kInitialWindow (10 * XQC_kMaxDatagramSize)
#define XQC_kLossReductionFactor (0.5f)


#define max(a, b) ((a) > (b) ? (a) : (b))

static inline uint64_t now()
{
    /*获取毫秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return  ul;
}

xqc_new_reno_t xqc_new_reno;

static xqc_int_t
xqc_reno_init (void **cong_ctl, xqc_connection_t *conn)
{
    *cong_ctl = &xqc_new_reno;

    xqc_new_reno_t *reno = (xqc_new_reno_t*)(*cong_ctl);

    reno->reno_congestion_window = XQC_kInitialWindow;
    reno->reno_ssthresh = 0xffffffff;

    return 0;
}

/**
 * InRecovery
 */
static int
xqc_reno_in_recovery(void *cong_ctl, xqc_msec_t sent_time)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return sent_time <= reno->reno_recovery_start_time;
}

static void
xqc_reno_on_lost (void *cong_ctl, xqc_msec_t lost_sent_time)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);

    // Start a new congestion event if the sent time is larger
    // than the start time of the previous recovery epoch.
    if (!xqc_reno_in_recovery(cong_ctl, lost_sent_time)) {
        reno->reno_recovery_start_time = now();
        reno->reno_congestion_window *= XQC_kLossReductionFactor;
        reno->reno_congestion_window = max(reno->reno_congestion_window, XQC_kMinimumWindow);
        reno->reno_ssthresh = reno->reno_congestion_window;
    }

}

static void
xqc_reno_on_ack (void *cong_ctl, xqc_msec_t sent_time, uint32_t n_bytes)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    if (xqc_reno_in_recovery(cong_ctl, sent_time)) {
        // Do not increase congestion window in recovery period.
        return;
    }

    if (reno->reno_congestion_window < reno->reno_ssthresh) {
        // Slow start.
        reno->reno_congestion_window += n_bytes;
    }
    else {
        // Congestion avoidance.
        reno->reno_congestion_window += XQC_kMaxDatagramSize * n_bytes / reno->reno_congestion_window;
    }
}

uint32_t
xqc_reno_get_cwnd (void *cong_ctl)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return reno->reno_congestion_window;
}

void
xqc_reno_reset_cwnd (void *cong_ctl)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    reno->reno_congestion_window = XQC_kMinimumWindow;
}

const xqc_cong_ctrl_callback_t xqc_reno_cb = {
    .xqc_cong_ctl_init      = xqc_reno_init,
    .xqc_cong_ctl_on_lost   = xqc_reno_on_lost,
    .xqc_cong_ctl_on_ack    = xqc_reno_on_ack,
    .xqc_cong_ctl_get_cwnd  = xqc_reno_get_cwnd,
    .xqc_cong_ctl_reset_cwnd = xqc_reno_reset_cwnd,
};
