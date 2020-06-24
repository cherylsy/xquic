
#ifndef _XQC_SEND_CTL_H_INCLUDED_
#define _XQC_SEND_CTL_H_INCLUDED_

#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_pacing.h"
#include "src/congestion_control/xqc_sample.h"

#define XQC_kPacketThreshold 3
#define XQC_kPersistentCongestionThreshold 2
/*Timer granularity.  This is a system-dependent value.
However, implementations SHOULD use a value no smaller than 1ms.*/
#define XQC_kGranularity 2
//#define XQC_kInitialRtt 500
#define XQC_kInitialRtt 250

//2^n
#define xqc_send_ctl_pow(n) (1 << n)

#define XQC_CTL_PACKETS_USED_MAX 16000

/*
 * A connection will time out if no packets are sent or received for a
   period longer than the time specified in the idle_timeout transport
   parameter (see Section 10).  However, state in middleboxes might time
   out earlier than that.  Though REQ-5 in [RFC4787] recommends a 2
   minute timeout interval, experience shows that sending packets every
   15 to 30 seconds is necessary to prevent the majority of middleboxes
   from losing state for UDP flows.
 */
#define XQC_PING_TIMEOUT 15000

/* !!warning add to timer_type_2_str */
typedef enum {
    XQC_TIMER_ACK_INIT,
    XQC_TIMER_ACK_HSK = XQC_TIMER_ACK_INIT + XQC_PNS_HSK,
    XQC_TIMER_ACK_01RTT = XQC_TIMER_ACK_INIT + XQC_PNS_01RTT,
    XQC_TIMER_LOSS_DETECTION,
    XQC_TIMER_IDLE,
    XQC_TIMER_DRAINING,
    XQC_TIMER_PACING,
    XQC_TIMER_STREAM_CLOSE,
    XQC_TIMER_PING,
    XQC_TIMER_N,
} xqc_send_ctl_timer_type;

typedef void (*xqc_send_ctl_timer_callback)(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx);

typedef struct {
    uint8_t                     ctl_timer_is_set;
    xqc_msec_t                  ctl_expire_time;
    void                        *ctl_ctx;
    xqc_send_ctl_timer_callback ctl_timer_callback;
    int                         ctl_pacing_time_isexpire;
} xqc_send_ctl_timer_t;


#define XQC_DEFAULT_RECORD_INTERVAL (100000)   //100毫秒的记录间隔
#define XQC_DEFAULT_RTT_CHANGE_THRESHOLD (50 * 1000) //50毫秒
#define XQC_DEFAULT_BW_CHANGE_THRESHOLD (50) //带宽改变的百分比
typedef struct {
    xqc_msec_t  last_record_time; //上次周期性记录的时间
    xqc_msec_t  last_rtt_time; //上次rtt发生大变化的时间
    xqc_msec_t  last_lost_time; //上次记录发生丢包的时间
    xqc_msec_t  last_bw_time; //上次记录bandwidth发生剧烈变化的时间
    uint64_t    record_interval; //所有类型的记录在该间隔内都只记录一次
    uint64_t    rtt_change_threshold; //rtt发生变化的阈值
    uint64_t    bw_change_threshold;//bandwidth发生变化的阈值
    uint64_t    last_lost_count;//上次记录的丢包数目
    uint64_t    last_send_count;//上次记录的发包数目
}xqc_send_ctl_info_t;

typedef struct xqc_send_ctl_s {
    xqc_list_head_t             ctl_send_packets; //xqc_packet_out_t to send
    xqc_list_head_t             ctl_send_packets_high_pri; //xqc_packet_out_t to send with high priority
    xqc_list_head_t             ctl_unacked_packets[XQC_PNS_N]; //xqc_packet_out_t
    xqc_list_head_t             ctl_lost_packets; //xqc_packet_out_t
    xqc_list_head_t             ctl_free_packets; //xqc_packet_out_t
    xqc_list_head_t             ctl_buff_1rtt_packets; //xqc_packet_out_t buff 1RTT before handshake complete
    unsigned                    ctl_packets_used;
    unsigned                    ctl_packets_free;
    unsigned                    ctl_packets_used_max;
    xqc_connection_t            *ctl_conn;

    xqc_packet_number_t         ctl_packet_number[XQC_PNS_N];

    /* 发送ACK且被ACK的packet_out中，Largest Acknowledged的最大值
     * 确保了ACK已被对端收到，因此发送方可以不再生成小于该值的ACK*/
    xqc_packet_number_t         ctl_largest_ack_both[XQC_PNS_N];

    /* 已发送的最大packet number */
    xqc_packet_number_t         ctl_largest_sent[XQC_PNS_N];

    /* 已接收的最大packet number */
    xqc_packet_number_t         ctl_largest_recvd[XQC_PNS_N];

    /* packet_out中被ACK的最大的packet number */
    xqc_packet_number_t         ctl_largest_acked[XQC_PNS_N];

    /* packet_out的发送时间 */
    xqc_msec_t                  ctl_largest_acked_sent_time[XQC_PNS_N];

    xqc_msec_t                  ctl_loss_time[XQC_PNS_N];

    xqc_msec_t                  ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_N];
    xqc_packet_number_t         ctl_last_sent_ack_eliciting_packet_number[XQC_PNS_N];
    xqc_msec_t                  ctl_srtt,
                                ctl_rttvar,
                                ctl_minrtt,
                                ctl_latest_rtt;

    xqc_send_ctl_timer_t        ctl_timer[XQC_TIMER_N];

    unsigned                    ctl_pto_count;

    unsigned                    ctl_send_count;
    unsigned                    ctl_lost_count;
    unsigned                    ctl_tlp_count;

    unsigned                    ctl_recv_count;

    unsigned                    ctl_bytes_in_flight;
    unsigned                    ctl_prior_bytes_in_flight;

    uint64_t                    ctl_bytes_send;
    uint64_t                    ctl_bytes_recv;

    const
    xqc_cong_ctrl_callback_t    *ctl_cong_callback;
    void                        *ctl_cong;

    xqc_pacing_t                ctl_pacing;

    uint64_t                    ctl_prior_delivered; /* the amount of data delivered in the last call of on_ack_received*/
    uint64_t                    ctl_delivered; /* 表示当前ack时刻已经标记为发送完毕的数据量 */
    uint64_t                    ctl_app_limited; /* The index of the last transmitted packet marked as
   application-limited, or 0 if the connection is not currently
   application-limited. */
    xqc_msec_t                  ctl_delivered_time; /* 当前packet P被ack的时间 */
    xqc_msec_t                  ctl_first_sent_time; /* 当前采样周期中第一个packet的发送时间 */

    xqc_sample_t                sampler;

    xqc_send_ctl_info_t         ctl_info;
} xqc_send_ctl_t;


static inline xqc_msec_t
xqc_send_ctl_calc_pto(xqc_send_ctl_t *ctl)
{
    return ctl->ctl_srtt + xqc_max(4 * ctl->ctl_rttvar, XQC_kGranularity*1000) +
           ctl->ctl_conn->local_settings.max_ack_delay*1000;
}

/*
 * 写缓存
 */
static inline int
xqc_send_ctl_can_write(xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_packets_used < ctl->ctl_packets_used_max) {
        return 1;
    }
    return 0;
}


xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn);

void
xqc_send_ctl_destroy(xqc_send_ctl_t *ctl);

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, xqc_pkt_type_t pkt_type);

void
xqc_send_ctl_destroy_packets_list(xqc_list_head_t *head);

void
xqc_send_ctl_destroy_packets_lists(xqc_send_ctl_t *ctl);

int
xqc_send_ctl_can_send (xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void
xqc_send_ctl_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_insert_unacked(xqc_packet_out_t *packet_out, xqc_list_head_t *head, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_remove_send(xqc_list_head_t *pos);

void
xqc_send_ctl_insert_send(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_remove_lost(xqc_list_head_t *pos);

void
xqc_send_ctl_insert_lost(xqc_list_head_t *pos, xqc_list_head_t *head);

void
xqc_send_ctl_remove_free(xqc_list_head_t *pos, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_insert_free(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_remove_buff(xqc_list_head_t *pos, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_insert_buff(xqc_list_head_t *pos, xqc_list_head_t *head);

void
xqc_send_ctl_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head);

void
xqc_send_ctl_move_to_high_pri(xqc_list_head_t *pos, xqc_send_ctl_t *ctl);

void
xqc_send_ctl_drop_packets(xqc_send_ctl_t *ctl);

void
xqc_send_ctl_drop_0rtt_packets(xqc_send_ctl_t *ctl);

void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out, xqc_msec_t now);

int
xqc_send_ctl_on_ack_received (xqc_send_ctl_t *ctl, xqc_ack_info_t *const ack_info, xqc_msec_t ack_recv_time);

void
xqc_send_ctl_update_rtt(xqc_send_ctl_t *ctl, xqc_msec_t *latest_rtt, xqc_msec_t ack_delay);

void
xqc_send_ctl_detect_lost(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pns, xqc_msec_t now);

int
xqc_send_ctl_in_persistent_congestion(xqc_send_ctl_t *ctl, xqc_packet_out_t *largest_lost);

int
xqc_send_ctl_is_window_lost(xqc_send_ctl_t *ctl, xqc_packet_out_t *largest_lost, xqc_msec_t congestion_period);

void
xqc_send_ctl_congestion_event(xqc_send_ctl_t *ctl, xqc_msec_t sent_time);

int
xqc_send_ctl_in_recovery(xqc_send_ctl_t *ctl, xqc_msec_t sent_time);

int
xqc_send_ctl_is_app_limited();

void
xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *ctl, xqc_packet_out_t *acked_packet, xqc_msec_t now);

void
xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *ctl);

xqc_msec_t
xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t *pns_ret);

xqc_msec_t
xqc_send_ctl_get_srtt(xqc_send_ctl_t *ctl);

float
xqc_send_ctl_get_retrans_rate(xqc_send_ctl_t *ctl);


/*
 * *****************TIMER*****************
 */
const char *
xqc_timer_type_2_str(xqc_send_ctl_timer_type timer_type);

void
xqc_send_ctl_timer_init(xqc_send_ctl_t *ctl);

static inline int
xqc_send_ctl_timer_is_set(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type)
{
    return ctl->ctl_timer[type].ctl_timer_is_set;
}

static inline void
xqc_send_ctl_timer_set(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type, xqc_msec_t expire)
{
    ctl->ctl_timer[type].ctl_timer_is_set = 1;
    ctl->ctl_timer[type].ctl_expire_time = expire;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|type:%s|expire:%ui|now:%ui|",
            xqc_timer_type_2_str(type), expire, xqc_now());
}

static inline void
xqc_send_ctl_timer_unset(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type)
{
    ctl->ctl_timer[type].ctl_timer_is_set = 0;
    ctl->ctl_timer[type].ctl_expire_time = 0;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|type:%s|",
            xqc_timer_type_2_str(type));
}

/*
 * add by zhiyou
 */
static inline void
xqc_send_pacing_timer_set(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type, xqc_msec_t expire) {
    ctl->ctl_timer[type].ctl_timer_is_set = 1;
    ctl->ctl_timer[type].ctl_expire_time = expire;

    ctl->ctl_timer[type].ctl_pacing_time_isexpire = 0;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|type:%s|expire:%ui|now:%ui|",
            xqc_timer_type_2_str(type), expire, xqc_now());
}

static inline void
xqc_send_pacing_timer_update(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type, xqc_msec_t new_expire) {

    if (new_expire - ctl->ctl_timer[type].ctl_expire_time < 1000)
        return;

    int was_set = ctl->ctl_timer[type].ctl_timer_is_set;

    if (was_set) {
        // update
        ctl->ctl_timer[type].ctl_expire_time = new_expire;
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|type:%s|new_expire:%ui|now:%ui|",
                xqc_timer_type_2_str(type), new_expire, xqc_now());
    } else {
        xqc_send_pacing_timer_set(ctl, type, new_expire);
    }

}

static inline int
xqc_send_pacing_timer_isset(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type) {
    return ctl->ctl_timer[type].ctl_timer_is_set;
}


static inline void
xqc_send_ctl_timer_expire(xqc_send_ctl_t *ctl, xqc_msec_t now)
{
    xqc_send_ctl_timer_t *timer;
    for (xqc_send_ctl_timer_type type = 0; type < XQC_TIMER_N; ++type) {
        timer = &ctl->ctl_timer[type];
        if (timer->ctl_timer_is_set && timer->ctl_expire_time <= now) {
            if(type == XQC_TIMER_IDLE){
                xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR,
                    "|conn:%p|timer expired|type:%s|expire_time:%ui|now:%ui|",
                    ctl->ctl_conn, xqc_timer_type_2_str(type), timer->ctl_expire_time, now);

            }else{
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                    "|timer expired|type:%s|expire_time:%ui|now:%ui|",
                    xqc_timer_type_2_str(type), timer->ctl_expire_time, now);
            }
            timer->ctl_timer_callback(type, now, timer->ctl_ctx);

            //unset timer if it is not updated in ctl_timer_callback
            if (timer->ctl_expire_time <= now) {
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                        "|unset|type:%s|expire_time:%ui|now:%ui|",
                        xqc_timer_type_2_str(type), timer->ctl_expire_time, now);
                xqc_send_ctl_timer_unset(ctl, type);
            }
        }
    }
}
/*
 * *****************TIMER END*****************
 */

#endif //_XQC_SEND_CTL_H_INCLUDED_
