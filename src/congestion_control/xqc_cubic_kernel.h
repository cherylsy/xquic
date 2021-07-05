#ifndef _XQC_CUBIC_KERNEL_H_INCLUDED_
#define _XQC_CUBIC_KERNEL_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_send_ctl.h"

/* BIC TCP Parameters */
typedef struct
{
    uint32_t        cnt;              /* increase cwnd by 1 after ACKs */
    uint32_t        last_max_cwnd;    /* last maximum snd_cwnd */
    uint32_t        last_cwnd;        /* the last snd_cwnd */
    xqc_usec_t      last_time;        /* time when updated last_cwnd */
    uint32_t        bic_origin_point; /* origin point of bic function */
    uint32_t        bic_K;            /* time to origin point
                                          from the beginning of the current epoch */
    xqc_usec_t      delay_min;        /* min delay (us) */
    xqc_usec_t      epoch_start;      /* beginning of an epoch */
    uint32_t        ack_cnt;          /* number of acks */
    uint32_t        tcp_cwnd;         /* estimated tcp cwnd */

    uint32_t        cwnd_cnt;   /* count the number of acked pkts since the last window increase. */
    uint32_t        init_cwnd;        /* 初始窗口大小,单位为MSS个数 */
    uint32_t        cwnd;             /* 当前的窗口大小,单位为PKts */
    uint32_t        ssthresh;         /* 慢启动阈值 in pkts*/

    uint64_t        prev_round_delivered;
    uint64_t        next_round_delivered; /* A sentiel to watch if the next round is started. */
    xqc_usec_t      current_round_mrtt;   /* min rtt of current round */
    xqc_usec_t      last_round_mrtt;      /* min rtt of last round */
    uint32_t        rtt_sample_cnt;
    uint8_t         in_lss;             /*is in Limited Slow Start*/
    uint32_t        lss_accumulated_bytes; 

    xqc_usec_t      recovery_start_time; /* 0 means not in recovery*/
    xqc_send_ctl_t *ctl_ctx;           /* To read ctl->ctl_delivered */
} xqc_cubic_kernel_t;

extern const xqc_cong_ctrl_callback_t xqc_cubic_kernel_cb;

#endif /* _XQC_CUBIC_H_INCLUDED_ */
