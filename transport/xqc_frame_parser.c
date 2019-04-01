
#include <string.h>
#include <sys/types.h>
#include "xqc_frame_parser.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_stream.h"


int
xqc_gen_stream_frame(unsigned char *dst_buf, size_t dst_buf_len,
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
    unsigned vlen;

    const unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    const unsigned char first_byte = *p++;

    p += xqc_vint_read(p, end, &stream_id);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);

    frame = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_frame_t));
    frame->stream_id = stream_id;

    if (first_byte & 0x04) {
        vlen = xqc_vint_read(p, end, &offset);
        if (vlen < 0) {
            return -1;
        }
        p += vlen;
        frame->data_offset = offset;
    } else {
        frame->data_offset = 0;
    }

    if (first_byte & 0x02) {
        vlen = xqc_vint_read(p, end, &length);
        if (vlen < 0) {
            return -1;
        }
        p += vlen;
        frame->data_length = length;
    } else {
        frame->data_length = end - p;
    }

    if (first_byte & 0x01) {
        frame->fin = 1;
    }
    else {
        frame->fin = 0;
    }

    //TODO: insert xqc_stream_frame_t into stream->stream_data_in.frames_tailq in order of offset

    packet_in->pos += (p - packet_in->buf + frame->data_length);
    return 0;
}

int
xqc_parse_frames(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    while (packet_in->pos < packet_in->last) {
        if(xqc_parse_stream_frame(packet_in, conn) != 0) {
            return -1;
        }
    }
    return 0;
}
