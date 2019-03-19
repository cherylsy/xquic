
#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include <sys/queue.h>
#include "../include/xquic_typedef.h"
#include "xqc_packet.h"
#include "../common/xqc_memory_pool.h"

typedef struct xqc_packet_out_s
{
    TAILQ_ENTRY(lsquic_packet_out)
                            po_next;
    unsigned char           *po_buf;
    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    xqc_packet_number_t     po_pktno;
    enum xqc_pkt_num_space
                            po_pns;
} xqc_packet_out_t;

xqc_packet_out_t *
xqc_alloc_packet_out (xqc_memory_pool_t *pool);

#endif //_XQC_PACKET_OUT_H_INCLUDED_
