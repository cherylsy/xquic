
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"
#include "xqc_frame.h"

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;
    TAILQ_INIT(&send_ctl->ctl_packets);
    return send_ctl;
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, unsigned need, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;

    TAILQ_FOREACH_REVERSE(packet_out, &ctl->ctl_packets, xqc_packets_tailq, po_next) {
        if (packet_out->po_pkt.pkt_pns == pns &&
            packet_out->po_buf_size - packet_out->po_used_size >= need) {
            return packet_out;
        }
    }

    packet_out = xqc_create_packet_out(ctl->ctl_conn->conn_pool, ctl, pns);
    if (packet_out == NULL) {
        return NULL;
    }


    return packet_out;
}

int
xqc_send_ctl_can_send (xqc_connection_t *conn)
{
    //TODO: check if can send
    return 1;
}