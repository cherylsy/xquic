#ifndef _XQC_PACKET_IN_H_INCLUDED_
#define _XQC_PACKET_IN_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_packet.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_frame.h"


struct xqc_packet_in_s
{
    xqc_packet_t            pi_pkt;
    xqc_list_head_t         pi_list;
    const unsigned char    *buf;
    size_t                  buf_size;
    const unsigned char    *decode_payload;
    size_t                  decode_payload_size;
    unsigned char          *pos;
    unsigned char          *last;
    xqc_msec_t              pkt_recv_time;  /* millisecond */
    xqc_frame_type_bit_t    pi_frame_types;
};


#define XQC_PACKET_IN_LEFT_SIZE(packet_in) (((packet_in)->pos < (packet_in)->last)?((packet_in)->last - (packet_in)->pos):0)


void
xqc_init_packet_in(xqc_packet_in_t *packet_in,
                   const unsigned char *packet_in_buf,
                   size_t packet_in_size,
                   const unsigned char *decode_payload,
                   size_t decode_payload_size,
                   xqc_msec_t recv_time);

#endif /* _XQC_PACKET_IN_H_INCLUDED_ */
