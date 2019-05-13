
#include <string.h>
#include <sys/types.h>
#include "xqc_frame_parser.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_stream.h"
#include "xqc_packet_out.h"
#include "xqc_packet_parser.h"


int
xqc_gen_stream_frame(xqc_packet_out_t *packet_out,
                     xqc_stream_id_t stream_id, size_t offset, uint8_t fin,
                     const unsigned char *payload, size_t size, size_t *written_size)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */

    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Stream ID (i)                       ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Offset (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Length (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Stream Data (*)                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    *written_size = 0;
    /*  variable length integer's most significant 2 bits */
    unsigned stream_id_bits, offset_bits, length_bits;
    /* variable length integer's size(byte) */
    unsigned stream_id_len, offset_len, length_len;
    /* 0b00001XXX point to second byte */
    unsigned char *p = dst_buf + 1;

    stream_id_bits = xqc_vint_get_2bit(stream_id);
    stream_id_len = xqc_vint_len(stream_id_bits);
    if (offset) {
        offset_bits = xqc_vint_get_2bit(offset);
        offset_len = xqc_vint_len(offset_bits);
    } else {
        offset_len = 0;
    }

    /* fin_only means there is no stream data */
    uint8_t fin_only = (fin && !size);

    if (!fin_only) {
        ssize_t n_avail;

        n_avail = dst_buf_len - (p + stream_id_len + offset_len - dst_buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size < n_avail) {
            length_bits = xqc_vint_get_2bit(size);
            length_len = xqc_vint_len(length_bits);
            n_avail -= length_len;
            if (size > n_avail) {
                size = n_avail;
            }
        } else {
            length_len = 0;
            size = n_avail;
            fin = 0;
        }

        if (n_avail <= 0 || size > n_avail) {
            return -1;
        }

        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;

        memcpy(p + length_len, payload, size);
        *written_size = size;

        if (length_len) {
            xqc_vint_write(p, size, length_bits, length_len);
        }

        p += length_len + size;
    } else {
        /* check if there is enough space to put Length */
        length_len = 1 + stream_id_len + offset_len < dst_buf_len ? 1 : 0;
        if (1 + stream_id_len + offset_len + length_len > dst_buf_len) {
            return -1;
        }
        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;
        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;
        if (length_len) {
            *p++ = 0;
        }
    }

    dst_buf[0] = 0x08
                 | (!!offset_len << 2)
                 | (!!length_len << 1)
                 | (!!fin << 0);

    packet_out->po_frame_types |= XQC_FRAME_BIT_STREAM;

    return p - dst_buf;
}

int
xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    xqc_stream_frame_t *frame;
    xqc_stream_t *stream;
    xqc_stream_id_t stream_id;

    uint64_t offset;
    uint64_t length;
    int vlen;

    const unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    const unsigned char first_byte = *p++;

    vlen = xqc_vint_read(p, end, &stream_id);
    if (vlen < 0) {
        return -1;
    }
    p += vlen;

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_stream_frame|cannot find stream|");
        return -2;
    }

    frame = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_frame_t));

    if (first_byte & 0x04) {
        vlen = xqc_vint_read(p, end, &offset);
        if (vlen < 0) {
            return -3;
        }
        p += vlen;
        frame->data_offset = offset;
    } else {
        frame->data_offset = 0;
    }

    if (first_byte & 0x02) {
        vlen = xqc_vint_read(p, end, &length);
        if (vlen < 0) {
            return -4;
        }
        p += vlen;
        frame->data_length = length;
    } else {
        frame->data_length = end - p;
    }

    if (first_byte & 0x01) {
        frame->fin = 1;
        stream->stream_data_in.fin_received = 1;
        stream->stream_data_in.stream_length = frame->data_offset + frame->data_length;
    }
    else {
        frame->fin = 0;
    }

    if (frame->data_length > 0) {
        frame->data = xqc_malloc(frame->data_length); //TODO: maybe use stream's pool?; free data
        if (!frame->data) {
            return -5;
        }
        memcpy(frame->data, p, frame->data_length);
    }

    //TODO: insert xqc_stream_frame_t into stream->stream_data_in.frames_tailq in order of offset
    xqc_stream_ready_to_read(stream);

    packet_in->pos += (p - packet_in->buf + frame->data_length);
    return 0;
}

int
xqc_gen_crypto_frame(xqc_packet_out_t *packet_out, size_t offset,
                     const unsigned char *payload, size_t payload_size, size_t *written_size)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    unsigned char offset_bits, length_bits;
    unsigned offset_vlen, length_vlen;
    unsigned char *begin = dst_buf;

    *dst_buf++ = 0x06;

    offset_bits = xqc_vint_get_2bit(offset);
    offset_vlen = xqc_vint_len(offset_bits);

    length_bits = xqc_vint_get_2bit(payload_size);
    length_vlen = xqc_vint_len(length_bits);

    if (1 + offset_vlen + length_vlen + 1 > dst_buf_len) {
        return -1;
    }

    xqc_vint_write(dst_buf, offset, offset_bits, offset_vlen);
    dst_buf += offset_vlen;

    *written_size = payload_size;
    if (1 + offset_vlen + length_vlen + payload_size > dst_buf_len) {
        *written_size = dst_buf_len - (1 + offset_vlen + length_vlen);
    }

    xqc_vint_write(dst_buf, *written_size, length_bits, length_vlen);
    dst_buf += length_vlen;

    memcpy(dst_buf, payload, *written_size);
    dst_buf += *written_size;

    packet_out->po_frame_types |= XQC_FRAME_BIT_CRYPTO;

    return dst_buf - begin;
}

int
xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    //TODO: 实现
    packet_in->pos = packet_in->last;
    return XQC_OK;
}

void
xqc_gen_padding_frame(xqc_packet_out_t *packet_out)
{
    if (packet_out->po_used_size < XQC_PACKET_INITIAL_MIN_LENGTH) {
        memset(packet_out->po_buf + packet_out->po_used_size, 0, XQC_PACKET_INITIAL_MIN_LENGTH - packet_out->po_used_size);
        packet_out->po_used_size = XQC_PACKET_INITIAL_MIN_LENGTH;
        xqc_long_packet_update_length(packet_out);
    }
    packet_out->po_frame_types |= XQC_FRAME_BIT_PADDING;
}

int
xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    packet_in->pos = packet_in->last;
    return XQC_OK;
}

/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Largest Acknowledged (i)                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Delay (i)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       ACK Range Count (i)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       First ACK Range (i)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Ranges (*)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          [ECN Counts]                       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Figure 17: ACK Frame Format
 */
int
xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
                  xqc_msec_t now, int ack_delay_exponent,
                      xqc_recv_record_t *recv_record, int *has_gap, xqc_packet_number_t *largest_ack)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    xqc_packet_number_t lagest_recv;
    xqc_msec_t ack_delay;

    const unsigned char *begin = dst_buf;
    const unsigned char *end = dst_buf + dst_buf_len;
    unsigned char *p_range_count;
    unsigned range_count = 0, first_ack_range, gap, acks, prev_low, gap_bits, acks_bits, need;

    xqc_list_head_t* pos;
    xqc_pktno_range_node_t *range_node;

    xqc_list_for_each(pos, &recv_record->list_head) {
        range_node = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        printf("xqc_gen_ack_frame low:%llu, high=%llu\n", range_node->pktno_range.low, range_node->pktno_range.high);
    }

    xqc_pktno_range_node_t *first_range =
            xqc_list_entry((&recv_record->list_head)->next, xqc_pktno_range_node_t, list);

    if (first_range == NULL) {
        return XQC_ERROR;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_gen_ack_frame|high: %ui, low: %ui|",
            first_range->pktno_range.high, first_range->pktno_range.low);

    lagest_recv = first_range->pktno_range.high;
    ack_delay = (now - recv_record->largest_pkt_recv_time) >> ack_delay_exponent;
    first_ack_range = lagest_recv - first_range->pktno_range.low;
    prev_low = first_range->pktno_range.low;

    unsigned lagest_recv_bits = xqc_vint_get_2bit(lagest_recv);
    unsigned ack_delay_bits = xqc_vint_get_2bit(ack_delay);
    unsigned first_ack_range_bits = xqc_vint_get_2bit(first_ack_range);

    need = 1    //type
            + xqc_vint_len(lagest_recv_bits)
            + xqc_vint_len(ack_delay_bits)
            + 1  //range_count
            + xqc_vint_len(first_ack_range_bits);

    if (dst_buf + need > end) {
        return XQC_ERROR;
    }

    *dst_buf++ = 0x02;

    xqc_vint_write(dst_buf, lagest_recv, lagest_recv_bits, xqc_vint_len(lagest_recv_bits));
    dst_buf += xqc_vint_len(lagest_recv_bits);

    *largest_ack = lagest_recv;

    xqc_vint_write(dst_buf, ack_delay, ack_delay_bits, xqc_vint_len(ack_delay_bits));
    dst_buf += xqc_vint_len(ack_delay_bits);

    p_range_count = dst_buf;
    dst_buf += 1; //max range_count 63, 1 byte

    xqc_vint_write(dst_buf, first_ack_range, first_ack_range_bits, xqc_vint_len(first_ack_range_bits));
    dst_buf += xqc_vint_len(first_ack_range_bits);

    int is_first = 1;
    xqc_list_for_each(pos, &recv_record->list_head) { //from second node
        if (is_first) {
            is_first = 0;
            continue;
        }
        range_node = xqc_list_entry(pos, xqc_pktno_range_node_t, list);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_gen_ack_frame|high: %ui, low: %ui|",
                range_node->pktno_range.high, range_node->pktno_range.low);

        gap = prev_low - range_node->pktno_range.high - 2;
        acks = range_node->pktno_range.high - range_node->pktno_range.low;

        gap_bits = xqc_vint_get_2bit(gap);
        acks_bits = xqc_vint_get_2bit(acks);

        need = xqc_vint_len(gap_bits) + xqc_vint_len(acks_bits);
        if (dst_buf + need > end) {
            return XQC_ERROR;
        }

        xqc_vint_write(dst_buf, gap, gap_bits, xqc_vint_len(gap_bits));
        dst_buf += xqc_vint_len(gap_bits);

        xqc_vint_write(dst_buf, acks, acks_bits, xqc_vint_len(acks_bits));
        dst_buf += xqc_vint_len(acks_bits);

        ++range_count;

        if (range_count >= 63) {
            break;
        }
    }

    if (range_count > 0) {
        *has_gap = 1;
    }
    xqc_vint_write(p_range_count, range_count, 0, 1);

    packet_out->po_frame_types |= XQC_FRAME_BIT_ACK;

    return dst_buf - begin;
}

/**
 * parse ack frame to ack_info
 */
int
xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;
    uint64_t largest_acked;
    uint64_t ack_range_count;
    uint64_t first_ack_range;
    uint64_t range, gap;

    unsigned n_ranges = 0;

    ack_info->pns = packet_in->pi_pkt.pkt_pns;

    vlen = xqc_vint_read(p, end, &largest_acked);
    if (vlen < 0) {
        return -1;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, &ack_info->ack_delay);
    if (vlen < 0) {
        return -2;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, &ack_range_count);
    if (vlen < 0) {
        return -3;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, &first_ack_range);
    if (vlen < 0) {
        return -4;
    }
    p += vlen;

    ack_info->ranges[n_ranges].high = largest_acked;
    ack_info->ranges[n_ranges].low = largest_acked - first_ack_range;
    n_ranges++;

    for (int i = 0; i < ack_range_count; ++i) {
        vlen = xqc_vint_read(p, end, &gap);
        if (vlen < 0) {
            return -5;
        }
        p += vlen;

        vlen = xqc_vint_read(p, end, &range);
        if (vlen < 0) {
            return -6;
        }
        p += vlen;

        ack_info->ranges[n_ranges].high = ack_info->ranges[n_ranges - 1].low - gap - 2;
        ack_info->ranges[n_ranges].low = ack_info->ranges[n_ranges].high - range;
        n_ranges++;
    }

    ack_info->n_ranges = n_ranges;

    packet_in->pos = p;

    return XQC_OK;
}