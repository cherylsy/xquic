#include "../include/xquic.h"
#include"xqc_bbr.h"
#include "xqc_window_filter.h"
#include "xqc_sample.h"

#define max(a,b) a>b?a:b
#define min(a,b) a<b?a:b

#define XQC_kMaxDatagramSize 1200
#define XQC_kMinimumWindow (4 * XQC_kMaxDatagramSize)
/*The RECOMMENDED value is the minimum of 10 *
kMaxDatagramSize and max(2* kMaxDatagramSize, 14720)).*/
#define XQC_kInitialWindow (10 * XQC_kMaxDatagramSize)



/**
 * Constants of BBR
 */
/*Pacing gain cycle rounds */
const uint32_t xqc_bbr_kCycleLength = 8;
/*Size of window of bandwidth filter, in rtts */
const uint32_t xqc_bbr_kBandwidthWindowSize = xqc_bbr_kCycleLength + 2;
/*Window of min rtt filter, in sec */
const uint32_t xqc_bbr_kMinRttWindowSize = 10;
/* Minimum time spent in BBR_PROBE_RTT, in usec*/
const uint32_t xqc_bbr_kProbeRttTime = 200;
/*Initial rtt before any samples are received  */
const uint64_t xqc_bbr_kInitialRtt = 100;
/*The gain of pacing rate for STRAT_UP, 2/(ln2) */
const float xqc_bbr_kHighGain = 2.885;
/*Gain in BBR_DRAIN */
const float xqc_bbr_kDrainGain = 1.0 / xqc_bbr_kHighGain;
/* Gain for cwnd in probe_bw, like slow start*/
const float xqc_bbr_kCwndGain = 2.0;
/*Cycle of gains in PROBE_BW for pacing rate */
const float xqc_bbr_kPacingGain[] = {1.25, 0.75, 1, 1, 1, 1, 1, 1};
/*Minimum packets that need to ensure ack if there is delayed ack */
const uint32_t xqc_bbr_kMinCongestionWindow = 4 * XQC_kMaxDatagramSize;
/*If bandwidth has increased by 1.25, there may be more bandwidth avaliable */
const float xqc_bbr_kFullBandWithThresh = 1.25;
/*After 3 rounds bandwidth less than (1.25x), estimate the pipe is full */
const uint32_t xqc_bbr_kFullBandwidthCnt = 3;
const float xqc_bbr_probe_rtt_gain = 0.75;
const uint32_t xqc_bbr_extra_ack_win_rtt = 10;
const uint32_t xqc_bbr_extra_ack_gain = 1;
const float xqc_bbr_max_extra_ack_time = 0.1;
const uint32_t  xqc_bbr_ack_epoch_acked_reset_thresh = 1<<20;

size_t xqc_bbr_size()
{
    return sizeof(xqc_bbr_t);
}

static void xqc_bbr_enter_startup(xqc_bbr_t *bbr)
{
    bbr->mode = BBR_STARTUP;
    bbr->pacing_gain = xqc_bbr_kHighGain;
    bbr->cwnd_gain = xqc_bbr_kHighGain;
}

static void xqc_bbr_init_pacing_rate(xqc_bbr_t *bbr,xqc_sample_t *sampler)
{
    uint32_t bandwidth;
    bandwidth = XQC_kInitialWindow / (sampler->srtt ? sampler->srtt : 0.001);
    bbr->pacing_rate = bbr->pacing_gain * bandwidth;
}

static void xqc_bbr_init(void *cong_ctl, xqc_sample_t *sampler)
{
    xqc_bbr_t *bbr = (xqc_bbr_t*)(cong_ctl);
    xqc_win_filter_reset(&bbr->bandwidth,0,0);
    bbr->min_rtt = sampler->srtt ? sampler->srtt : 0x7fffffff;
    bbr->min_rtt_stamp = sampler->now;
    bbr->round_start = 0;
    bbr->round_cnt = 0;
    bbr->next_round_delivered = 0;
    bbr->probe_rtt_round_done = false;
    bbr->probe_rtt_round_done_stamp = 0;
    bbr->packet_conservation = false;
    bbr->prior_cwnd = 0;
    bbr->initial_congestion_window = 10 * XQC_kMaxDatagramSize;

    bbr->extra_ack_stamp = sampler->now;
    bbr->epoch_ack = 0;
    bbr->extra_ack_round_rtt= 0;
    bbr->extra_ack_idx = 0;
    bbr->extra_ack[0] = 0;
    bbr->extra_ack[1] = 0;

    bbr->full_bandwidth_cnt = 0;
    bbr->full_bandwidth_reached = false;
    
    xqc_bbr_enter_startup(bbr);
    xqc_bbr_init_pacing_rate(bbr,sampler);

}

static uint32_t xqc_bbr_max_bw(xqc_bbr_t *bbr)
{
    return xqc_win_filter_get(&bbr->bandwidth);
}

static void xqc_bbr_update_bandwidth(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    /*Check whether the data is legal */
    if(sampler->delivered < 0 || sampler->interval <= 0)
        return;
    
    /**
     * 这里是用来检测是否到达下一个BBR周期
     * 条件语句表示：周期开始的时候，发送完毕的packet数量小于等于当前ack的包在发送时
     * 已经发送完毕的packet最大数量
     */
    if(bbr->next_round_delivered <= sampler->prior_delivered)
    {
        bbr->next_round_delivered = sampler->total_acked;
        bbr->round_cnt++;
        bbr->round_start = true;

    }else
    {
        bbr->round_start = false;
    }
    
    uint32_t bandwidth;
    /*Calculate the new bandwidth, bytes per second */
    bandwidth = sampler->delivered / sampler->interval * msec2sec;

    if(!sampler->is_app_limited || bandwidth >= xqc_bbr_max_bw(bbr))
    {
        xqc_win_filter_max(&bbr->bandwidth, xqc_bbr_kBandwidthWindowSize, bbr->round_cnt, bandwidth);
    }
}

static void xqc_bbr_update_cycle_phase(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    bool advnce_gain_cycle = (sampler->now - bbr->cycle_start_stamp) > bbr->min_rtt;
    uint32_t inflight = sampler->bytes_inflight;

    if(bbr->pacing_gain > 1 && !sampler->loss
       && inflight < bbr->congestion_window){
           advnce_gain_cycle = false;
       }
    if(bbr->pacing_gain < 1
       && inflight < bbr->congestion_window){
           advnce_gain_cycle = true;
       }
    if(bbr->mode == BBR_PROBE_BW && advnce_gain_cycle){
        bbr->cycle_idx = (bbr->cycle_idx + 1) % xqc_bbr_kCycleLength;
        bbr->last_cycle_start = sampler->now;
    }
}



static uint32_t xqc_bbr_extra_ack(xqc_bbr_t *bbr)
{
    return max(bbr->extra_ack[0], bbr->extra_ack[1]);
}


static uint32_t xqc_bbr_ack_aggregation_cwnd(xqc_bbr_t *bbr)
{
    uint32_t max_aggr_cwnd, aggr_cwnd = 0;
    if(xqc_bbr_extra_ack_gain && bbr->full_bandwidth_reached)
    {
        max_aggr_cwnd = xqc_bbr_max_bw(bbr) * xqc_bbr_max_extra_ack_time;
        aggr_cwnd = xqc_bbr_extra_ack_gain * xqc_bbr_extra_ack(bbr);
        aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
    }
    return aggr_cwnd;
}

static void xqc_update_ack_aggregation(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    uint32_t epoch, expected_ack, extra_ack;
    if (!xqc_bbr_extra_ack_gain|| sampler->delivered <= 0
        || sampler->interval <= 0)
        return;
    if (bbr->round_start) {
        bbr->extra_ack_round_rtt += 1;
        // 每10个rtt作为一轮参与计算。
        if (bbr->extra_ack_round_rtt >= xqc_bbr_extra_ack_win_rtt) {
            bbr->extra_ack_round_rtt = 0;
            bbr->extra_ack_idx = bbr->extra_ack_idx ?0 : 1;
            bbr->extra_ack[bbr->extra_ack_idx] = 0;
        }
    }

    epoch = sampler->now - bbr->extra_ack_stamp;
    expected_ack = ((uint64_t )xqc_bbr_max_bw(bbr) * epoch) / msec2sec;

    if (bbr->epoch_ack <= expected_ack
        || (bbr->epoch_ack + sampler->delivered >= xqc_bbr_ack_epoch_acked_reset_thresh)) {
        bbr->epoch_ack = 0;
        bbr->extra_ack_stamp = sampler->now;
        expected_ack = 0;
    }
    /* Compute excess data delivered, beyond what was expected. */
    bbr->epoch_ack = min(0xFFFFFU, bbr->epoch_ack + sampler->delivered);
    extra_ack = bbr->epoch_ack - expected_ack;
    extra_ack = min(extra_ack, bbr->congestion_window);

    if (extra_ack > bbr->extra_ack[bbr->extra_ack_idx])
        bbr->extra_ack[bbr->extra_ack_idx] = extra_ack;
}




static void xqc_bbr_check_full_bw_reached(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    if(bbr->full_bandwidth_reached || sampler->is_app_limited ){
        return;
    }

    uint32_t bw_thresh = bbr->last_bandwidth * xqc_bbr_kFullBandWithThresh;
    if(xqc_bbr_max_bw(bbr) >= bw_thresh){
        bbr->last_bandwidth = xqc_bbr_max_bw(bbr);
        bbr->full_bandwidth_cnt = 0;
        return;
    }
    ++bbr->full_bandwidth_cnt;
    bbr->full_bandwidth_reached = bbr->full_bandwidth_cnt >= xqc_bbr_kFullBandwidthCnt;
}

static void xqc_bbr_enter_drain(xqc_bbr_t *bbr)
{
    bbr->mode = BBR_DRAIN;
    bbr->pacing_gain = xqc_bbr_kDrainGain;
    bbr->cwnd_gain = xqc_bbr_kHighGain;
}

static uint32_t xqc_bbr_target_cwnd(xqc_bbr_t *bbr, float gain)
{
    if(bbr->min_rtt == 0x7fffffff){
        return bbr->initial_congestion_window;
    }

    uint32_t bdp,cwnd;
    bdp = bbr-> min_rtt * xqc_win_filter_get(&bbr->bandwidth) / msec2sec;
    cwnd = gain * bdp;
    return max(cwnd, XQC_kMinimumWindow);
}

static void xqc_bbr_enter_probe_bw(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    bbr->mode = BBR_PROBE_BW;
    bbr->cwnd_gain = xqc_bbr_kCwndGain;
    /**
     * bbr->cycle_idx = random(0,7);
     * if(bbr->cycle_idx == 1)
     *  ++bbr->cycle_idx;
     */
    bbr->cycle_idx = 0;
    bbr->pacing_gain = xqc_bbr_kPacingGain[bbr->cycle_idx];
    bbr->cycle_start_stamp = sampler->now;
}

static void xqc_bbr_check_drain(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    if(bbr->mode == BBR_STARTUP && bbr->full_bandwidth_reached)
        xqc_bbr_enter_drain(bbr);
    
    if(bbr->mode == BBR_DRAIN && sampler->bytes_inflight <= xqc_bbr_target_cwnd(bbr, 1.0))
        xqc_bbr_enter_probe_bw(bbr,sampler);
}

static void xqc_bbr_update_min_rtt(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    bbr->min_rtt_expired = (bbr->min_rtt != 0 
                       && sampler->now > bbr->min_rtt_stamp + xqc_bbr_kMinRttWindowSize * msec2sec);
    
    if((sampler->rtt >= 0 && sampler->rtt <= bbr->min_rtt)
        || bbr->min_rtt_expired){
        bbr->min_rtt = sampler->rtt;
        bbr->min_rtt_stamp = sampler->now;
    }
}

static void xqc_bbr_enter_probe_rtt(xqc_bbr_t *bbr)
{
    bbr->mode = BBR_PROBE_RTT;
    bbr->pacing_gain = 1;
    bbr->cwnd_gain = 1;
}

static void xqc_bbr_save_cwnd(xqc_bbr_t *bbr,xqc_sample_t *sampler)
{
    if(!sampler->loss && bbr->mode != BBR_PROBE_RTT)
        bbr->prior_cwnd = bbr->congestion_window;
    else
        bbr->prior_cwnd = max(bbr->congestion_window, bbr->prior_cwnd);
    
}
static void xqc_bbr_restore_cwnd(xqc_bbr_t *bbr)
{
    bbr->congestion_window = max(bbr->congestion_window, bbr->prior_cwnd);
}

static void xqc_bbr_exit_probe_rtt(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    if(bbr->full_bandwidth_reached){
        xqc_bbr_enter_probe_bw(bbr,sampler);

    }else {
        xqc_bbr_enter_startup(bbr);
    }
}

static void xqc_bbr_check_probe_rtt(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    if(bbr->min_rtt_expired && bbr->mode != BBR_PROBE_RTT){
        xqc_bbr_enter_probe_rtt(bbr);
        xqc_bbr_save_cwnd(bbr,sampler);
        bbr->probe_rtt_round_done_stamp = 0;
    }
    if(bbr->mode == BBR_PROBE_RTT){
        if(!bbr->probe_rtt_round_done_stamp 
           && (sampler->bytes_inflight <= xqc_bbr_kMinCongestionWindow
               || sampler->bytes_inflight <= xqc_bbr_max_bw(bbr) * xqc_bbr_probe_rtt_gain)){
               bbr->probe_rtt_round_done_stamp = sampler->now + xqc_bbr_kProbeRttTime * 1000;
               bbr->probe_rtt_round_done = false;
               bbr->next_round_delivered = sampler->total_acked;

        } else if(bbr->probe_rtt_round_done_stamp){
            if(bbr->round_start)
                bbr->probe_rtt_round_done = 1;
            if(bbr->probe_rtt_round_done && bbr->probe_rtt_round_done_stamp < sampler->now){
                bbr->min_rtt_stamp = sampler->now;
                xqc_bbr_restore_cwnd(bbr);
                xqc_bbr_exit_probe_rtt(bbr, sampler);
            }
                
        }
    }
}

static uint64_t xqc_bbr_get_min_rtt(xqc_bbr_t *bbr)
{

    return bbr->min_rtt == 0 ? xqc_bbr_kInitialRtt : bbr->min_rtt;
}

static void xqc_bbr_set_pacing_rate(xqc_bbr_t *bbr)
{
    uint32_t bandwidth,rate;
    bandwidth = xqc_bbr_max_bw(bbr);
    rate = bandwidth * bbr->pacing_gain;
    if(bbr->pacing_rate == 0){
        bbr->pacing_rate = xqc_bbr_kHighGain * (bbr->initial_congestion_window / xqc_bbr_get_min_rtt(bbr) * msec2sec);
    }
        

    if(bbr->full_bandwidth_reached || rate > bbr->pacing_rate)
        bbr->pacing_rate = rate;
}


static void xqc_bbr_set_cwnd(xqc_bbr_t *bbr, xqc_sample_t *sampler)
{
    uint32_t target_cwnd;
    target_cwnd = xqc_bbr_target_cwnd(bbr,bbr->cwnd_gain);
    target_cwnd += xqc_bbr_ack_aggregation_cwnd(bbr);

    if(bbr->full_bandwidth_reached)
        bbr->congestion_window = min(target_cwnd,bbr->congestion_window + sampler->delivered);
    else if(bbr->congestion_window < target_cwnd)
        bbr->congestion_window += sampler->delivered;

    bbr->congestion_window = max(bbr->congestion_window, xqc_bbr_kMinCongestionWindow);
    if(bbr->mode == BBR_PROBE_RTT)
        bbr->congestion_window = min(bbr->congestion_window, xqc_bbr_kMinCongestionWindow);
}

static void xqc_bbr_on_ack(void *cong_ctl, xqc_sample_t *sampler)
{
    xqc_bbr_t *bbr = (xqc_bbr_t*)(cong_ctl);

    /*Update model and state*/
    xqc_bbr_update_bandwidth(bbr,sampler);
    xqc_bbr_update_cycle_phase(bbr,sampler);
    xqc_bbr_check_full_bw_reached(bbr,sampler);
    xqc_bbr_check_drain(bbr,sampler);
    xqc_bbr_update_min_rtt(bbr,sampler);
    xqc_bbr_check_probe_rtt(bbr,sampler);

    /*Update control parameter */
    xqc_bbr_set_pacing_rate(bbr);
    xqc_bbr_set_cwnd(bbr,sampler);

}

static uint32_t xqc_bbr_get_cwnd(void *cong_ctl)
{
    xqc_bbr_t *bbr = (xqc_bbr_t*)(cong_ctl);
    return bbr->congestion_window;
}

static uint32_t  xqc_bbr_get_pacing_rate(void *cong_ctl)
{
    xqc_bbr_t *bbr = (xqc_bbr_t*)(cong_ctl);
    return bbr->pacing_rate;
}

const xqc_cong_ctrl_callback_t xqc_bbr_cb = {
    .xqc_cong_ctl_size          = xqc_bbr_size,
    .xqc_cong_ctl_bbr_init      = xqc_bbr_init,
    .xqc_cong_ctl_bbr           = xqc_bbr_on_ack,
    .xqc_cong_ctl_get_cwnd      = xqc_bbr_get_cwnd,
};
