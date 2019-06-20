#include "xqc_packet_in.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_conn.h"


/* 未使用 */
xqc_packet_in_t *
xqc_create_packet_in (xqc_connection_t *conn,
                      const unsigned char *packet_in_buf,
                      size_t packet_in_size, xqc_msec_t recv_time)
{
    xqc_packet_in_t *packet_in;
    packet_in = xqc_calloc(1, sizeof(xqc_packet_in_t));
    if (!packet_in) {
        return NULL;
    }
    xqc_list_add_tail(&packet_in->pi_list, &conn->packet_in_tailq);

    xqc_init_packet_in(packet_in, packet_in_buf, packet_in_size, recv_time);

    return packet_in;
}

void
xqc_init_packet_in(xqc_packet_in_t *packet_in, const unsigned char *packet_in_buf,
                   size_t packet_in_size, xqc_msec_t recv_time)
{
    packet_in->buf = packet_in_buf;
    packet_in->buf_size = packet_in_size;
    packet_in->pos = (unsigned char *)packet_in_buf;
    packet_in->last = (unsigned char *)packet_in_buf + packet_in_size;
    packet_in->pkt_recv_time = recv_time;
}
