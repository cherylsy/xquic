
#ifndef _XQC_SEND_CTL_H_INCLUDED_
#define _XQC_SEND_CTL_H_INCLUDED_

#include <sys/queue.h>
#include "xqc_packet_out.h"
#include "xqc_conn.h"


typedef struct xqc_send_ctl_s {
    xqc_list_head_t             ctl_packets; //xqc_packet_out_t
    xqc_list_head_t             ctl_unacked_packets[XQC_PNS_N]; //xqc_packet_out_t
    xqc_connection_t            *ctl_conn;
    /* 已发送的最大packet number*/
    xqc_packet_number_t         ctl_largest_sent;
    /* packet_out中被ACK的最大的packet number */
    xqc_packet_number_t         ctl_largest_acked;
    /* packet_out的发送时间 */
    xqc_msec_t                  ctl_largest_acked_sent_time;

    /* 发送ACK且被ACK的packet_out中，Largest Acknowledged的最大值
     * 确保了ACK已被对端收到，因此发送方可以不再生成小于该值的ACK*/
    xqc_packet_number_t         ctl_largest_ack_both[XQC_PNS_N];

} xqc_send_ctl_t;

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn);

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, enum xqc_pkt_num_space pns);

int
xqc_send_ctl_can_send (xqc_connection_t *conn);

#endif //_XQC_SEND_CTL_H_INCLUDED_
