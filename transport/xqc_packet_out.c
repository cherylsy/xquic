#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_send_ctl.h"

#define XQC_PACKET_OUT_SIZE 1280    //TODO 先写死

xqc_packet_out_t *
xqc_create_packet_out (xqc_memory_pool_t *pool, xqc_send_ctl_t *ctl, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_pcalloc(pool, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_buf = xqc_pnalloc(pool, XQC_PACKET_OUT_SIZE);
    if (!packet_out->po_buf) {
        return NULL;
    }

    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_pns = pns;

    //TODO calc packet number
    packet_out->po_pkt.pkt_num = 0;

    TAILQ_INSERT_TAIL(&ctl->ctl_packets, packet_out, po_next);

    return packet_out;
}

