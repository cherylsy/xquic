#include "xqc_packet_in.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_conn.h"




void
xqc_init_packet_in(xqc_packet_in_t *packet_in,
                   const unsigned char *packet_in_buf,
                   size_t packet_in_size,
                   const unsigned char *decode_payload,
                   size_t decode_payload_size,
                   xqc_msec_t recv_time)
{
    packet_in->buf = packet_in_buf;
    packet_in->buf_size = packet_in_size;
    packet_in->decode_payload = decode_payload;
    packet_in->decode_payload_size = decode_payload_size;
    packet_in->pos = (unsigned char *)packet_in_buf;
    packet_in->last = (unsigned char *)packet_in_buf + packet_in_size;
    packet_in->pkt_recv_time = recv_time;
}
