#ifndef _XQC_SAMPLE_H_INCLUDED_
#define _XQC_SAMPLE_H_INCLUDED_

#include "include/xquic_typedef.h"

typedef char bool;
#define true 1
#define false 0

typedef struct xqc_sample_s{
    /*采样时间点 */
    xqc_msec_t  now;
    /*当前ack的packet在发送的时候传输完成的packet数目 */
    uint32_t    prior_delivered;
    /*两次采样的时间间隔 */
    xqc_msec_t  interval;
    /*两次采样之间传输完成(ack)的数据量 */
    uint32_t    delivered;
    /*发送但未收到ack的数据量 */
    uint32_t    bytes_inflight;
    /*采样所得的rtt */
    xqc_msec_t  rtt;
    uint32_t    is_app_limited;
    /*是否出现丢包情况 */
    uint32_t    loss;
    uint32_t    total_acked;
    xqc_msec_t  srtt;
    xqc_msec_t  prior_time;
    xqc_msec_t  ack_elapse;
    xqc_msec_t  send_elapse;
    uint32_t    delivery_rate;
} xqc_sample_t;

uint32_t xqc_generate_sample(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl);
void xqc_update_sample(xqc_sample_t *sample, xqc_packet_out_t *packet, xqc_send_ctl_t *send_ctl);

#endif