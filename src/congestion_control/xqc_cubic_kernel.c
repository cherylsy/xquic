#include "src/congestion_control/xqc_cubic_kernel.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/xqc_config.h"
#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet.h"
#include <math.h>
#include <stdio.h>

#define XQC_CUBIC_BETA_SCALE 1024 /* Scale factor beta calculation \
                                * max_cwnd= snd_cwnd * beta    \
                                */
#define XQC_CUBIC_HZ 10           /* BIC HZ 2^10= 1024 */
#define XQC_CUBIC_UPDATE_INTERVAL_US (31250) /* 1/32 * 1000000 us*/
#define XQC_CUBIC_USEC_PER_SEC (1000000)

/* We implement hystart++ instead of hystart. */
/* https://tools.ietf.org/id/draft-balasubramanian-tcpm-hystartplusplus-01.html */
/* Number of delay samples for detecting the increase of delay */
#define XQC_HSPP_MIN_SAMPLES        8
#define XQC_HSPP_DELAY_MIN_US       (4000U)     /*4ms*/
#define XQC_HSPP_DELAY_MAX_US       (16000U)    /*16ms*/
#define XQC_HSPP_DELAY_THRESH(x)    xqc_clamp(x, XQC_HSPP_DELAY_MIN_US, XQC_HSPP_DELAY_MAX_US)
#define XQC_HSPP_LSS_DIVISOR_SHIFT  (2)         /*1>>2 = 1/4 = 0.25*/
#define XQC_HSPP_LSS_STATE_INIT     (0)         /*LSS has not started yet*/
#define XQC_HSPP_LSS_STATE_START    (1)         /*In LSS*/
#define XQC_HSPP_LSS_STATE_END      (2)
#define XQC_INF_RTT                 (~0ULL)
#define XQC_HSPP_MIN_SSTHRESH       (16)        /*16 pkts*/

#define xqc_64_before(x, y)         ((int64_t)(x - y) < 0)
#define xqc_64_before_eq(x, y)      ((int64_t)(x - y) <= 0)
#define xqc_64_after(x, y)          (!xqc_before_eq(x, y))
#define xqc_64_after_eq(x, y)       (!xqc_before(x, y))

#define beta_base                   717
#define beta_lastmax_base           871
#define beta_with_N_conns(b, N) \
        (((N - 1) * XQC_CUBIC_BETA_SCALE + b + N - 1) / (N))
#define num_conns 2 /*to compete with two RENO conns*/
static int fast_convergence = 1;
static int beta = beta_with_N_conns(beta_base, num_conns); /* = 717/1024 (XQC_CUBIC_BETA_SCALE) */
static int beta_lastmax = beta_with_N_conns(beta_lastmax_base, num_conns);
static int initial_ssthresh;
static int bic_scale = 41;
static int tcp_friendliness = 1;
static uint8_t hystartpp_on = 1;
static uint32_t cube_rtt_scale;
static uint32_t beta_scale;
static uint64_t cube_factor;

#define XQC_CUBIC_MSS           (1460)
#define XQC_CUBIC_MAX_SSTHRESH  (~0U)
#define XQC_CUBIC_MIN_WIN       (4 * XQC_CUBIC_MSS)
#define XQC_CUBIC_MAX_INIT_WIN  (100 * XQC_CUBIC_MSS)
#define XQC_CUBIC_INIT_WIN      (32 * XQC_CUBIC_MSS)

static inline int
xqc_fls(uint32_t x)
{
    int r = 32;
    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static int 
xqc_fls64(uint64_t x)
{
    uint32_t h = x >> 32;
    if (h)
        return xqc_fls(h) + 32;
    return xqc_fls(x);
}

/**
 * do_div - returns 2 values: calculate remainder and update new dividend
 * @n: pointer to uint64_t dividend (will be updated)
 * @base: uint32_t divisor
 *
 * Summary:
 * ``uint32_t remainder= *n % base;``
 * ``*n= *n / base;``
 *
 * Return: (uint32_t)remainder
 *
 * NOTE: macro parameter @n is evaluated multiple times,
 * beware of side effects!
 */
#define xqc_do_div(n, base) ({          \
    uint32_t __base= (base);            \
    uint32_t __rem;                     \
    __rem= ((uint64_t)(n)) % __base;    \
    (n)= ((uint64_t)(n)) / __base;      \
    __rem;                              \
})

static inline uint64_t 
xqc_div64_u64(uint64_t dividend, uint64_t divisor)
{
    return dividend / divisor;
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static uint32_t 
xqc_cubic_root(uint64_t a)
{
    uint32_t x, b, shift;
    /*
     * cbrt(x) MSB values for x MSB values in [0..63].
     * Precomputed then refined by hand - Willy Tarreau
     *
     * For x in [0..63],
     *   v= cbrt(x << 18) - 1
     *   cbrt(x)= (v[x] + 10) >> 6
     */
    static const uint8_t v[] = {
        /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
        /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
        /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
        /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
        /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
        /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
        /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
        /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
    };

    b = xqc_fls64(a);
    if (b < 7) {
        /* a in [0..63] */
        return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
    }
    b = ((b * 84) >> 8) - 1;
    shift = (a >> (b * 3));
    x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;
    /*
     * Newton-Raphson iteration
     *                         2
     * x   = ( 2 * x  +  a / x  ) / 3
     *  k+1          k         k
     */
    x = (2 * x + (uint32_t) xqc_div64_u64(a, (uint64_t) x * (uint64_t) (x - 1)));
    x = ((x * 341) >> 10);
    return x;
}

static int
xqc_cubic_in_recovery(void *cong) {
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t *)(cong);
    return ca->recovery_start_time > 0;
}

static inline void 
xqc_cubic_reset(void *cong)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t *)(cong);
    ca->cnt= 0;
    ca->last_cwnd= 0;
    ca->last_time= 0;
    ca->bic_origin_point= 0;
    ca->bic_K= 0;
    ca->delay_min= 0;
    ca->epoch_start= 0;
    ca->ack_cnt= 0;
    ca->tcp_cwnd= 0;
    ca->recovery_start_time = 0;
}

static void 
xqc_cubic_init(void *cong, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    /* Precompute a bunch of the scaling factors that are used per-packet
    * based on SRTT of 100ms
    */
    beta_scale = 8 * (XQC_CUBIC_BETA_SCALE + beta) / 3 / (XQC_CUBIC_BETA_SCALE - beta) / num_conns / num_conns;
    cube_rtt_scale = (bic_scale * 10); /* 1024*c/rtt */
    /* calculate the "K" for (wmax-cwnd)= c/rtt * K^3F
    *  so K= cubic_root( (wmax-cwnd)*rtt/c )
    * the unit of K is bictcp_HZ=2^10, not HZ
    *
    *  c= bic_scale >> 10
    *  rtt= 100ms
    *
    * the following code has been designed and tested for
    * cwnd < 1 million packets
    * RTT < 100 seconds
    * HZ < 1,000,00  (corresponding to 10 nano-second)
    */
    /* 1/c * 2^2*bictcp_HZ * srtt */
    cube_factor= 1ull << (10 + 3 * XQC_CUBIC_HZ); /* 2^40 */
    /* divide by bic_scale and by constant Srtt (100ms) */
    xqc_do_div(cube_factor, bic_scale * 10);

    xqc_cubic_reset(ca);
    ca->last_max_cwnd = 0;
    ca->init_cwnd = XQC_CUBIC_INIT_WIN;

    if (cc_params.customize_on) {
        cc_params.init_cwnd *= XQC_CUBIC_MSS;
        ca->init_cwnd = xqc_clamp(cc_params.init_cwnd, XQC_CUBIC_MIN_WIN,
                                  XQC_CUBIC_MAX_INIT_WIN);
    }

    ca->init_cwnd /= XQC_CUBIC_MSS;
    ca->cwnd = ca->init_cwnd;
    ca->cwnd_cnt = 0;
    ca->ssthresh = XQC_CUBIC_MAX_SSTHRESH;

    ca->current_round_mrtt = XQC_INF_RTT;
    ca->last_round_mrtt = XQC_INF_RTT;
    ca->rtt_sample_cnt = 0;

    ca->ctl_ctx = ctl_ctx;
    ca->prev_round_delivered = ctl_ctx->ctl_delivered;
    ca->next_round_delivered = ctl_ctx->ctl_delivered;
    ca->in_lss = XQC_HSPP_LSS_STATE_INIT;
    ca->lss_accumulated_bytes = 0;
}

/* @last_snd_time: the time when the last pkt (except pure ACK and CONN_CLOSE) was sent */
static void 
xqc_cubic_restart_from_idle(void *cong, xqc_usec_t last_snd_time)
{
    if (last_snd_time == 0) {
        return;
    }
    
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    xqc_usec_t now = xqc_monotonic_timestamp();
    /* We were application limited (idle) for a while.
     * Shift epoch_start to keep cwnd growth to cubic curve.
     */
    if (ca->epoch_start && now > last_snd_time) {
        ca->epoch_start += now - last_snd_time;
        if (ca->epoch_start > now) {
            ca->epoch_start = now;   
        }
    }
}

/*
 * Compute congestion window to use.
 */
static inline void 
xqc_cubic_update(void *cong, uint32_t acked, xqc_usec_t now)
{
    uint32_t delta, bic_target, max_cnt;
    uint64_t offs, t;
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);

    ca->ack_cnt += acked; /* count the number of ACKed packets */

    /*If our cwnd has not been changed for just a while*/
    if (ca->last_cwnd == ca->cwnd 
        && (now - ca->last_time) <= XQC_CUBIC_UPDATE_INTERVAL_US) 
    {
        return;
    }
        
    /* The CUBIC function can update ca->cnt at most once per jiffy.
     * On all cwnd reduction events, ca->epoch_start is set to 0,
     * which will force a recalculation of ca->cnt.
     */
    if (ca->epoch_start && now == ca->last_time) {
        goto tcp_friendliness;
    }

    ca->last_cwnd= ca->cwnd;
    ca->last_time= now;

    if (ca->epoch_start == 0) {
        ca->epoch_start = now;           /* record beginning */
        ca->ack_cnt = acked;             /* start counting */
        ca->tcp_cwnd= ca->cwnd;          /* syn with cubic */
        if (ca->last_max_cwnd <= ca->cwnd)
        {
            ca->bic_K= 0;
            ca->bic_origin_point= ca->cwnd;
        }
        else
        {
            ca->bic_K= xqc_cubic_root(cube_factor * (ca->last_max_cwnd - ca->cwnd));
            ca->bic_origin_point= ca->last_max_cwnd;
        }
    }
    /* cubic function - calc*/
    /* calculate c * time^3 / rtt,
     *  while considering overflow in calculation of time^3
     * (so time^3 is done by using 64 bit)
     * and without the support of division of 64bit numbers
     * (so all divisions are done by using 32 bit)
     *  also NOTE the unit of those veriables
     *      time = (t - K) / 2^bictcp_HZ
     *      c= bic_scale >> 10
     * rtt = (srtt >> 3) / HZ
     * !!! The following code does not have overflow problems,
     * if the cwnd < 1 million packets !!!
     */
    t = (now + ca->delay_min - ca->epoch_start); /*us*/
    /* change the unit from us to bictcp_HZ */
    t <<= XQC_CUBIC_HZ;
    t /= XQC_CUBIC_USEC_PER_SEC;
    if (t < ca->bic_K) /* t - K */
        offs = ca->bic_K - t;
    else
        offs = t - ca->bic_K;
    /* c/rtt * (t-K)^3 */
    delta = (cube_rtt_scale * offs * offs * offs) >> (10 + 3 * XQC_CUBIC_HZ);
    if (t < ca->bic_K) /* below origin*/
        bic_target = ca->bic_origin_point - delta;
    else /* above origin*/
        bic_target = ca->bic_origin_point + delta;
    /* cubic function - calc bictcp_cnt*/
    if (bic_target > ca->cwnd)
    {
        ca->cnt = ca->cwnd / (bic_target - ca->cwnd);
    }
    else
    {
        ca->cnt = 100 * ca->cwnd; /* very small increment*/
    }

    /*
     * The initial growth of cubic function may be too conservative
     * when the available bandwidth is still unknown.
     */
    if (ca->last_max_cwnd == 0 && ca->cnt > 20)
        ca->cnt = 20; /* increase cwnd 5% per RTT */

tcp_friendliness:
    /* TCP Friendly */
    if (tcp_friendliness) {
        uint32_t scale = beta_scale;
        delta = (ca->cwnd * scale) >> 3;
        while (ca->ack_cnt > delta) { /* update tcp cwnd */
            ca->ack_cnt -= delta;
            ca->tcp_cwnd++;
        }
        if (ca->tcp_cwnd > ca->cwnd) { /* if bic is slower than tcp */
            delta = ca->tcp_cwnd - ca->cwnd;
            max_cnt = ca->cwnd / delta;
            if (ca->cnt > max_cnt)
                ca->cnt = max_cnt;
        }
    }
    /* The maximum rate of cwnd increase CUBIC allows is 1 packet per
     * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
     */
    ca->cnt= xqc_max(ca->cnt, 2U);
}

static int 
xqc_cubic_in_slow_start(void *cong) 
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    return ca->cwnd < ca->ssthresh;
}

static inline uint32_t 
xqc_cubic_slow_start(void *cong, uint32_t acked) 
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    uint32_t cwnd = xqc_min(ca->cwnd + acked, ca->ssthresh);
    acked -= cwnd - ca->cwnd;
    ca->cwnd = cwnd;
    return acked;
}

static inline uint32_t 
xqc_cubic_cong_avoid_ai(void *cong, uint32_t w, uint32_t acked) {
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    uint32_t acc_inc = 0;
    uint32_t delta = 0;
    if (ca->cwnd_cnt >= w) {
        /* If credits accumulated at a higher w, apply them gently now. */
        ca->cwnd_cnt = 0;
        acc_inc = 1;
    }
    ca->cwnd_cnt += acked;
    if (ca->cwnd_cnt >= w) {
         delta = ca->cwnd_cnt / w;
         ca->cwnd_cnt -= delta * w;
    }
    return ca->cwnd + acc_inc + delta;
}

static void
xqc_cubic_maintain_hspp_state(xqc_cubic_kernel_t *ca, 
    xqc_packet_out_t *po, xqc_usec_t rtt)
{
    if (rtt != 0) {
        /*A new round starts*/
        if (po->po_delivered >= ca->next_round_delivered) {
            ca->prev_round_delivered = ca->next_round_delivered;
            ca->next_round_delivered = ca->ctl_ctx->ctl_delivered;
            ca->last_round_mrtt = ca->current_round_mrtt;
            ca->current_round_mrtt = rtt;
            ca->rtt_sample_cnt = 1;
        } else {
            /* Do sampling */
            /* We do not want samples not from pkts sent in this round. */
            if (po->po_delivered >= ca->prev_round_delivered) {
                ca->current_round_mrtt = xqc_min(ca->current_round_mrtt, rtt);
                ca->rtt_sample_cnt += 1;
            }
        }
    }
}

static void
xqc_cubic_hspp_try_to_enter_lss(xqc_cubic_kernel_t *ca) {
    if (ca->cwnd >= XQC_HSPP_MIN_SSTHRESH 
        && ca->rtt_sample_cnt >= XQC_HSPP_MIN_SAMPLES 
        && ca->last_round_mrtt != XQC_INF_RTT)
    {
        xqc_usec_t eta = xqc_clamp(ca->last_round_mrtt>>3, 
                                   XQC_HSPP_DELAY_MIN_US,
                                   XQC_HSPP_DELAY_MAX_US);
        if (ca->current_round_mrtt >= (ca->last_round_mrtt + eta)) {
            ca->ssthresh = ca->cwnd;
            ca->in_lss = XQC_HSPP_LSS_STATE_START;
            ca->last_max_cwnd = ca->cwnd; 
            /*To enable cubic increase cwnd based on the cubic curve instead of 5% each RTT*/
        }
    }
}

static void 
xqc_cubic_on_ack(void *cong, xqc_packet_out_t *po, xqc_usec_t now)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    xqc_usec_t sent_time = po->po_sent_time;
    uint32_t acked_pkts = xqc_max(1U, po->po_used_size / XQC_CUBIC_MSS);
    xqc_usec_t rtt_us = now > sent_time ? now - sent_time : 0;
    uint32_t new_cwnd, cubic_cwnd, lss_cwnd;

    if (ca->delay_min == 0 || ca->delay_min >= rtt_us) {
        ca->delay_min = rtt_us;
    }

    if (sent_time > ca->recovery_start_time) {
        /* we have exited the recovery period. */
        ca->recovery_start_time = 0;
    }

    if (xqc_cubic_in_recovery(ca)) {
        /* Do not increase cwnd in recovery mode */
        return;
    }

    if (!xqc_send_ctl_is_cwnd_limited(ca->ctl_ctx)) {
        return;
    }
    
    if (xqc_cubic_in_slow_start(ca))
    {
        acked_pkts = xqc_cubic_slow_start(ca, acked_pkts);
        if (ca->in_lss == XQC_HSPP_LSS_STATE_INIT && hystartpp_on) {
            xqc_cubic_maintain_hspp_state(ca, po, rtt_us);
            xqc_cubic_hspp_try_to_enter_lss(ca);
        }
        if (!acked_pkts)
            return;
    }
    xqc_cubic_update(ca, acked_pkts, now);
    new_cwnd = xqc_cubic_cong_avoid_ai(ca, ca->cnt, acked_pkts);
    if (ca->in_lss == XQC_HSPP_LSS_STATE_START && hystartpp_on) {
        /*convert to bytes*/
        cubic_cwnd = (new_cwnd * XQC_CUBIC_MSS) 
                      + (ca->cwnd_cnt * XQC_CUBIC_MSS) / ca->cnt;
        ca->lss_accumulated_bytes += (acked_pkts * XQC_CUBIC_MSS 
                                      * ca->ssthresh / ca->cwnd) >> XQC_HSPP_LSS_DIVISOR_SHIFT;
        lss_cwnd = (ca->cwnd * XQC_CUBIC_MSS) + ca->lss_accumulated_bytes;
        if (lss_cwnd > cubic_cwnd) {
            /*LSS roughly increases cwnd by 1 pkt for every 4 ACKs at the beginning.
              Then, it slows down as cwnd getting larger and larger.*/
            new_cwnd = (lss_cwnd / XQC_CUBIC_MSS);
            ca->lss_accumulated_bytes = (lss_cwnd - new_cwnd * XQC_CUBIC_MSS);
            ca->cwnd_cnt = 0; /* since we adopt lss_cwnd, we should clear the accumulated cwnd credits of cubic*/
        } else {
            /* we should clear the accumulated bytes of lss. */
            ca->lss_accumulated_bytes = 0;
        }
    }
    ca->cwnd = new_cwnd;
}

static void 
xqc_cubic_on_lost(void *cong, xqc_usec_t lost_sent_time)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    if (xqc_cubic_in_recovery(ca)) {
        return;
    }

    ca->recovery_start_time = xqc_monotonic_timestamp();
    ca->epoch_start = 0; /* end of epoch */
    ca->in_lss = XQC_HSPP_LSS_STATE_END; /* end of limited slow start. */
    /* Wmax and fast convergence */
    if (ca->cwnd < ca->last_max_cwnd && fast_convergence) {
        ca->last_max_cwnd = (ca->cwnd * beta_lastmax) / XQC_CUBIC_BETA_SCALE;
    } else {
        ca->last_max_cwnd = ca->cwnd;
    }
    ca->cwnd_cnt = 0;
    ca->ssthresh = xqc_max((ca->cwnd * beta) / XQC_CUBIC_BETA_SCALE, XQC_CUBIC_MIN_WIN / XQC_CUBIC_MSS);
    ca->cwnd = ca->ssthresh;
}

/* handle persistent congestions here. */
static void 
xqc_cubic_reset_cwnd(void *cong)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong);
    /*If we come here, we have ssthresh and last_max_cwnd set by on_lost()*/
    ca->cwnd = XQC_CUBIC_MIN_WIN / XQC_CUBIC_MSS;
    ca->cwnd_cnt = 0;
    ca->in_lss = XQC_HSPP_LSS_STATE_END;
    /*reset will cancel the current recovery epoch.*/
    xqc_cubic_reset(ca);
}

/*
 * 返回拥塞算法结构体大小
 */
static size_t
xqc_cubic_size ()
{
    return sizeof(xqc_cubic_kernel_t);
}

/*
 * 返回拥塞窗口
 */
static uint64_t
xqc_cubic_get_cwnd (void *cong_ctl)
{
    xqc_cubic_kernel_t *ca = (xqc_cubic_kernel_t*)(cong_ctl);
    return (uint64_t)ca->cwnd * XQC_CUBIC_MSS;
}


const xqc_cong_ctrl_callback_t xqc_cubic_kernel_cb = {
        .xqc_cong_ctl_size              = xqc_cubic_size,
        .xqc_cong_ctl_init              = xqc_cubic_init,
        .xqc_cong_ctl_on_lost           = xqc_cubic_on_lost,
        .xqc_cong_ctl_on_ack            = xqc_cubic_on_ack,
        .xqc_cong_ctl_get_cwnd          = xqc_cubic_get_cwnd,
        .xqc_cong_ctl_reset_cwnd        = xqc_cubic_reset_cwnd,
        .xqc_cong_ctl_in_slow_start     = xqc_cubic_in_slow_start,
        .xqc_cong_ctl_restart_from_idle = xqc_cubic_restart_from_idle,
        .xqc_cong_ctl_in_recovery       = xqc_cubic_in_recovery,
};