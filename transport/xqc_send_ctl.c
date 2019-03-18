
#include "xqc_send_ctl.h"
#include "xqc_packet.h"
#include "xqc_packet_out.h"

xqc_send_ctl_t *
xqc_send_ctl_create (xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->sc_conn = conn;
    return send_ctl;
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out (xqc_send_ctl_t *ctl, enum xqc_pkt_num_space pns)
{
    xqc_packet_out_t *packet_out;
    TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_scheduled_packets, xqc_packets_tailq, po_next){
        if (packet_out->po_pns == pns) {
            return packet_out;
        }
    }

    packet_out = xqc_alloc_packet_out(ctl->sc_conn->conn_pool);
    if (packet_out == NULL) {
        return NULL;
    }

    packet_out->po_pns = pns;

    return packet_out;
}

