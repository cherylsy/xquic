#ifndef _XQC_RECV_RECORD_H_INCLUDED_
#define _XQC_RECV_RECORD_H_INCLUDED_

#include "xqc_packet.h"

typedef enum
{
    XQC_PKTRANGE_OK,
    XQC_PKTRANGE_DUP,
    XQC_PKTRANGE_ERR,
} xqc_pkt_range_status;

typedef struct xqc_pktno_range_s {
    xqc_packet_number_t low, high;
} xqc_pktno_range_t;

typedef struct xqc_pktno_range_node_s {
    xqc_pktno_range_t   pktno_range;
    xqc_list_head_t     list;
} xqc_pktno_range_node_t;

typedef struct xqc_recv_record_s {
    xqc_list_head_t         list_head; //xqc_pktno_range_node_t
    xqc_msec_t              largest_pkt_recv_time;
    xqc_packet_number_t     rr_del_from;
} xqc_recv_record_t;

typedef struct xqc_ack_info_s {
    xqc_pkt_num_space_t     pns;
    unsigned                n_ranges;  /* must > 0 */
    xqc_pktno_range_t       ranges[64];
    xqc_msec_t              ack_delay;
} xqc_ack_info_t;

void xqc_recv_record_del (xqc_recv_record_t *recv_record, xqc_packet_number_t del_from);

xqc_pkt_range_status xqc_recv_record_add (xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number,
                                          xqc_msec_t recv_time);

xqc_packet_number_t xqc_recv_record_largest(xqc_recv_record_t *recv_record);

void xqc_maybe_should_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns, int out_of_order, xqc_msec_t now);


#endif /* _XQC_RECV_RECORD_H_INCLUDED_ */
