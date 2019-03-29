#ifndef _XQC_PACKET_IN_H_INCLUDED_
#define _XQC_PACKET_IN_H_INCLUDED_

#include <sys/queue.h>
#include "../include/xquic_typedef.h"
#include "xqc_packet.h"
#include "../common/xqc_memory_pool.h"

TAILQ_HEAD(xqc_packet_in_tailq, xqc_packet_in_s);
typedef struct xqc_packet_in_tailq xqc_packet_in_tailq_t;

typedef struct xqc_packet_in_s
{
    xqc_packet_t            pi_pkt;
    TAILQ_ENTRY(xqc_packet_in_s)
                            pi_next;
    const unsigned char     *pi_buf;
    unsigned int            pi_header_size;
    unsigned int            pi_buf_size;
    uint64_t                pkt_recv_time;  /* millisecond */
    unsigned int            processed_offset;
} xqc_packet_in_t;


xqc_packet_in_t *
xqc_create_packet_in(xqc_memory_pool_t *pool, xqc_packet_in_tailq_t *tailq,
                     const unsigned char *packet_in_buf,
                     size_t packet_in_size, uint64_t recv_time);

#endif /* _XQC_PACKET_IN_H_INCLUDED_ */
