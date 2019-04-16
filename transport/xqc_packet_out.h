
#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include <sys/queue.h>
#include "../include/xquic_typedef.h"
#include "xqc_packet.h"
#include "../common/xqc_memory_pool.h"


typedef enum {
RESERVE
} xqc_packet_out_flag_t;

typedef struct xqc_packet_out_s
{
    xqc_packet_t            po_pkt;
    xqc_list_head_t         po_list;
    unsigned char           *po_buf;
    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    xqc_packet_out_flag_t   po_flag;
    unsigned char           *plength;
    /* Largest Acknowledged in ACK frame, if there is no ACK frame, it should be 0 */
    xqc_packet_number_t     po_largest_ack;
    xqc_msec_t              po_sent_time;

} xqc_packet_out_t;

xqc_packet_out_t *
xqc_create_packet_out (xqc_memory_pool_t *pool, xqc_send_ctl_t *ctl, enum xqc_pkt_num_space pns);

int
xqc_should_generate_ack(xqc_connection_t *conn);

int
xqc_write_ack_to_packets(xqc_connection_t *conn);

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

#endif //_XQC_PACKET_OUT_H_INCLUDED_
