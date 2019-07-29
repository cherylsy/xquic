#ifndef _XQC_CUBIC_H_INCLUDED_
#define _XQC_CUBIC_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "../include/xquic.h"

typedef struct {
    uint64_t        cwnd;
    uint64_t        tcp_cwnd; /* 按照Reno算法计算得的cwnd */
    uint64_t        last_max_cwnd;
    uint64_t        ssthresh;
    uint64_t        bic_origin_point; /* 新的Wmax保活点 */
    double          bic_K;
    xqc_msec_t      epoch_start; /* 拥塞状态切换开始的时刻 */
} xqc_cubic_t;

extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;

#endif /* _XQC_CUBIC_H_INCLUDED_ */
