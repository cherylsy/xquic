
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_conn.h"


xqc_int_t
xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                             unsigned char *buf, size_t size)
{
    

    return XQC_OK;
}


ssize_t
xqc_conn_process_single_packet(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    ssize_t res = 0;

    if (xqc_conn_check_handshake_completed(c)) {

    }

    return res;
}


/**
 * 1 UDP payload = n QUIC packets
 */
xqc_int_t
xqc_conn_process_packets(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    ssize_t res = 0;

    while (packet_in->pos < packet_in->last) {

        res = xqc_conn_process_single_packet(c, packet_in);

        /* err in parse packet, TODO: res == 0 */
        if (res <= 0) {
            xqc_log(c->log, XQC_LOG_WARN, "process packets err|%zd|%p|%p|%zu|", 
                                          res, (void *)packet_in->pos,
                                          (void *)packet_in->buf, packet_in->buf_size);
            return XQC_ERROR;
        }

        packet_in->pos += (size_t)res;
    }

    return XQC_OK;
}


