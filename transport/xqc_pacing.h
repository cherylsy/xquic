#ifndef _XQC_PACING_H_INCLUDED_
#define _XQC_PACING_H_INCLUDED_

#include <include/xquic_typedef.h>

struct xqc_send_ctl_t;

typedef struct xqc_pacing_s {
    xqc_msec_t          next_send_time;
    xqc_msec_t          now;
    uint32_t            burst_num;
    int                 timer_expire;
    int                 on;
} xqc_pacing_t;

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on);

int
xqc_pacing_is_on(xqc_pacing_t *pacing);

uint64_t
xqc_pacing_rate_calc(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

xqc_msec_t
xqc_pacing_time_cost(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

void
xqc_pacing_schedule(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

int
xqc_pacing_can_send(xqc_pacing_t *pacing, xqc_send_ctl_t *ctl);

#endif /* _XQC_PACING_H_INCLUDED_ */
