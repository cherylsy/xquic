#include <sys/queue.h>
#include "xqc_packet_in.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_conn.h"


/* TODO: reuse freed packets */
xqc_packet_in_t *
xqc_create_packet_in (xqc_memory_pool_t *pool, xqc_packet_in_tailq_t *tailq,
                      const unsigned char *packet_in_buf,
                      size_t packet_in_size, xqc_msec_t recv_time)
{
    xqc_packet_in_t *packet_in;
    packet_in = xqc_pcalloc(pool, sizeof(xqc_packet_in_t));
    if (!packet_in) {
        return NULL;
    }
    TAILQ_INSERT_TAIL(tailq, packet_in, pi_next);

    packet_in->buf = packet_in_buf;
    packet_in->buf_size = packet_in_size;
    packet_in->pos = packet_in_buf;
    packet_in->last = packet_in_buf + packet_in_size;
    packet_in->pkt_recv_time = recv_time;

    return packet_in;
}