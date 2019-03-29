#include <sys/queue.h>
#include "xqc_packet_in.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_conn.h"

xqc_packet_in_t *
xqc_create_packet_in (xqc_memory_pool_t *pool, xqc_packet_in_tailq_t *tailq,
                      const unsigned char *packet_in_buf,
                      size_t packet_in_size, uint64_t recv_time)
{
    xqc_packet_in_t *packet_in;
    packet_in = xqc_pcalloc(pool, sizeof(xqc_packet_in_t));
    if (!packet_in) {
        return NULL;
    }
    TAILQ_INSERT_TAIL(tailq, packet_in, pi_next);

    packet_in->pi_buf = packet_in_buf;
    packet_in->pi_buf_size = packet_in_size;
    packet_in->pkt_recv_time = recv_time;

    return packet_in;
}