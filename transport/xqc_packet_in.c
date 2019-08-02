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

void
xqc_destroy_packet_in(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    xqc_free((void*)packet_in->buf);
    xqc_free((void*)packet_in->decode_payload);
    xqc_free(packet_in);
}

void
xqc_buff_undecrypt_packet_in(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    xqc_packet_in_t *new_packet = xqc_calloc(1, sizeof(xqc_packet_in_t));
    new_packet->pi_pkt = packet_in->pi_pkt;
    new_packet->buf = xqc_malloc(packet_in->buf_size);
    new_packet->buf_size = packet_in->buf_size;
    xqc_memcpy((unsigned char *)new_packet->buf, packet_in->buf, packet_in->buf_size);
    new_packet->pos = (unsigned char *)new_packet->buf + (packet_in->pos - packet_in->buf);
    new_packet->last = (unsigned char *)new_packet->buf + (packet_in->last - packet_in->buf);
    new_packet->pkt_recv_time = packet_in->pkt_recv_time;

    xqc_list_add_tail(&new_packet->pi_list, &conn->undecrypt_packet_in);
    conn->undecrypt_count++;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|undecrypt_count:%ui|", conn->undecrypt_count);
}