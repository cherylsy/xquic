#ifndef _XQC_CUBIC_H_INCLUDED_
#define _XQC_CUBIC_H_INCLUDED_

#include "include/xquic_typedef.h"
#include "include/xquic.h"

typedef struct {
    uint32_t        init_cwnd;  /* 初始窗口大小,单位为MSS个数 */
    uint32_t        cwnd;       /* 当前的窗口大小,单位为字节 */
    uint32_t        tcp_cwnd;   /* 按照Reno算法计算得的cwnd */
    uint32_t        last_max_cwnd; /* 丢包降窗前的窗口 */
    uint32_t        ssthresh;   /* 慢启动阈值 */
    uint32_t        bic_origin_point; /* Wmax饱和点 */
    uint32_t        bic_K;      /* 代表从W增长到Wmax的时间周期 */
    xqc_msec_t      epoch_start; /* 拥塞状态切换开始的时刻,单位microsecond微秒 */
    xqc_msec_t      min_rtt;
} xqc_cubic_t;

extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;

#endif /* _XQC_CUBIC_H_INCLUDED_ */
