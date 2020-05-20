#ifndef _XQC_NEW_RENO_H_INCLUDED_
#define _XQC_NEW_RENO_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

typedef struct {
    unsigned        reno_congestion_window;
    unsigned        reno_ssthresh;
    xqc_msec_t      reno_recovery_start_time;
} xqc_new_reno_t;

extern const xqc_cong_ctrl_callback_t xqc_reno_cb;

#endif /* _XQC_NEW_RENO_H_INCLUDED_ */
