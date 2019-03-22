
#ifndef _XQC_SEND_CTL_H_INCLUDED_
#define _XQC_SEND_CTL_H_INCLUDED_

#include <sys/queue.h>
#include "xqc_packet_out.h"
#include "xqc_conn.h"

TAILQ_HEAD(xqc_packets_tailq, xqc_packet_out_t);

typedef struct xqc_send_ctl_s {
    struct xqc_packets_tailq    ctl_packets;
    xqc_connection_t            *ctl_conn;
} xqc_send_ctl_t;

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn);

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, enum xqc_pkt_num_space pns);

#endif //_XQC_SEND_CTL_H_INCLUDED_
