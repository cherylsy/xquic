#ifndef _XQC_PACING_H_INCLUDED_
#define _XQC_PACING_H_INCLUDED_

#include <xquic/xquic_typedef.h>

#define INFINITE_TIME 0xffffffffffffff0

struct xqc_send_ctl_t;

typedef struct xqc_pacing_s {
    xqc_msec_t          next_send_time;
    xqc_msec_t          now;
    uint32_t            burst_num;
    int                 timer_expire;
    int                 on;

    /* add by zhiyou */
    int pacing_limited;
    uint32_t burst_tokens;
    uint64_t ideal_next_packet_send_time;
    uint32_t initial_burst_size;
    uint32_t lumpy_tokens;
    uint64_t alarm_granularity;

} xqc_pacing_t;

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on, xqc_send_ctl_t *ctl);

/**
 * @return 是否启用pacing
 */
static inline int
xqc_pacing_is_on(xqc_pacing_t *pacing)
{
    return pacing->on;
}

uint64_t
xqc_pacing_rate_calc(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

xqc_msec_t
xqc_pacing_time_cost(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

void
xqc_pacing_schedule(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

int
xqc_pacing_can_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

/* add by zhiyou */
void xqc_pacing_on_packet_sent(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
                               xqc_connection_t *conn, xqc_packet_out_t *packet_out);

uint64_t xqc_pacing_time_until_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
                                    xqc_connection_t *conn, xqc_packet_out_t *packet_out);

int xqc_pacing_can_write(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl,
                         xqc_connection_t *conn, xqc_packet_out_t *packet_out);

#endif /* _XQC_PACING_H_INCLUDED_ */
