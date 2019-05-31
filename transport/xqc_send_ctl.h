
#ifndef _XQC_SEND_CTL_H_INCLUDED_
#define _XQC_SEND_CTL_H_INCLUDED_

#include <sys/queue.h>
#include "xqc_packet_out.h"
#include "xqc_conn.h"


#define XQC_kPacketThreshold 3
#define XQC_kPersistentCongestionThreshold 2
/*Timer granularity.  This is a system-dependent value.
However, implementations SHOULD use a value no smaller than 1ms.*/
#define XQC_kGranularity 1
#define XQC_kInitialRtt 100

//2^n
#define xqc_send_ctl_pow(n) (1 << n)

typedef enum {
    XQC_TIMER_ACK_INIT,
    XQC_TIMER_ACK_HSK = XQC_TIMER_ACK_INIT + XQC_PNS_HSK,
    XQC_TIMER_ACK_01RTT = XQC_TIMER_ACK_INIT + XQC_PNS_01RTT,
    XQC_TIMER_LOSS_DETECTION,
    XQC_TIMER_N,
} xqc_send_ctl_timer_type;

typedef void (*xqc_send_ctl_timer_callback)(xqc_send_ctl_timer_type type, xqc_msec_t now, void *ctx);

typedef struct {
    uint8_t                     ctl_timer_is_set;
    xqc_msec_t                  ctl_expire_time;
    void                        *ctl_ctx;
    xqc_send_ctl_timer_callback ctl_timer_callback;
} xqc_send_ctl_timer_t;

typedef struct xqc_send_ctl_s {
    xqc_list_head_t             ctl_packets; //xqc_packet_out_t to send
    xqc_list_head_t             ctl_unacked_packets[XQC_PNS_N]; //xqc_packet_out_t
    xqc_list_head_t             ctl_lost_packets; //xqc_packet_out_t
    xqc_list_head_t             ctl_free_packets; //xqc_packet_out_t
    unsigned                    ctl_packets_used;
    unsigned                    ctl_packets_free;
    xqc_connection_t            *ctl_conn;

    xqc_packet_number_t         ctl_packet_number[XQC_PNS_N];

    /* 发送ACK且被ACK的packet_out中，Largest Acknowledged的最大值
     * 确保了ACK已被对端收到，因此发送方可以不再生成小于该值的ACK*/
    xqc_packet_number_t         ctl_largest_ack_both[XQC_PNS_N];

    /* 已发送的最大packet number*/
    xqc_packet_number_t         ctl_largest_sent;

    /* packet_out中被ACK的最大的packet number */
    xqc_packet_number_t         ctl_largest_acked[XQC_PNS_N];

    /* packet_out的发送时间 */
    xqc_msec_t                  ctl_largest_acked_sent_time[XQC_PNS_N];

    xqc_msec_t                  ctl_loss_time[XQC_PNS_N];

    xqc_msec_t                  ctl_time_of_last_sent_crypto_packet;
    xqc_msec_t                  ctl_time_of_last_sent_ack_eliciting_packet;
    xqc_msec_t                  ctl_srtt,
                                ctl_rttvar,
                                ctl_minrtt,
                                ctl_latest_rtt;

    xqc_send_ctl_timer_t        ctl_timer[XQC_TIMER_N];

    unsigned                    ctl_pto_count;
    unsigned                    ctl_crypto_count;

    unsigned                    ctl_bytes_in_flight;
    unsigned                    ctl_crypto_bytes_in_flight;

    const
    xqc_cong_ctrl_callback_t    *ctl_cong_callback;
    void                        *ctl_cong;

} xqc_send_ctl_t;


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
xqc_send_ctl_can_send (xqc_connection_t *conn);

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
xqc_send_ctl_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head);

void
xqc_send_ctl_timer_init(xqc_send_ctl_t *ctl);

void
xqc_send_ctl_timer_expire(xqc_send_ctl_t *ctl, xqc_msec_t now);

static inline void
xqc_send_ctl_timer_set(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type, xqc_msec_t expire)
{
    ctl->ctl_timer[type].ctl_timer_is_set = 1;
    ctl->ctl_timer[type].ctl_expire_time = expire;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_timer_set|type=%d|expire=%ui|",
        type, expire);
}

static inline void
xqc_send_ctl_timer_unset(xqc_send_ctl_t *ctl, xqc_send_ctl_timer_type type)
{
    ctl->ctl_timer[type].ctl_timer_is_set = 0;
    ctl->ctl_timer[type].ctl_expire_time = 0;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_timer_unset|type=%d|",
            type);
}

void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out);

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
xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *ctl, xqc_packet_out_t *acked_packet);

void
xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *ctl);

xqc_msec_t
xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t *pns_ret);

#endif //_XQC_SEND_CTL_H_INCLUDED_
