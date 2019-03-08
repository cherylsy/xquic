
#include "xqc_frame_parser.h"
#include "../common/xqc_variable_len_int.h"

#define CHECK_STREAM_SPACE(need, pstart, pend) do {                 \
    if ((intptr_t) (need) > ((pend) - (pstart))) {                  \
        return -((int) (need));                                     \
    }                                                               \
} while (0)

static int
gen_stream_frame(unsigned char *dst_buf, size_t dst_buf_len,
                 xqc_stream_id_t stream_id, uint64_t offset, int fin_only, size_t size,
                 gsf_read_f gsf_read, void *stream)
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

    /*  variable length integer's most significant 2 bits */
    unsigned stream_id_bits, offset_bits, length_bits;
    /* variable length integer's size(byte) */
    unsigned stream_id_len, offset_len, length_len;
    /* 0b00001XXX point to second byte */
    unsigned char *p = dst_buf + 1;

    stream_id_bits = vint_get_2bit(stream_id);
    stream_id_len = vint_len(stream_id_bits);
    if (offset) {
        offset_bits = vint_get_2bit(offset);
        offset_len = vint_len(offset_bits);
    } else
        offset_len = 0;

    /* fin_only means there is no stream data */
    int fin = 0;

    if (!fin_only) {
        unsigned n_avail;
        size_t nr;

        n_avail = dst_buf_len - (p + stream_id_len + offset_len - dst_buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size < n_avail) {
            length_bits = vint_get_2bit(size);
            length_len = vint_len(length_bits);
            n_avail -= length_len;
            if (size > n_avail)
                size = n_avail;
        } else {
            length_len = 0;
            size = n_avail;
        }

        CHECK_STREAM_SPACE(1 + offset_len + stream_id_len + length_len +
                           +1 /* We need to write at least 1 byte */, dst_buf, dst_buf + dst_buf_len);

        vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len)
            vint_write(p, offset, offset_bits, offset_len);
        p += offset_len;

        /*
         * read size byte to p+length_len
         */
        nr = gsf_read(stream, p + length_len, size, &fin);
        assert(nr != 0);
        assert(nr <= size);

        if (length_len)
            vint_write(p, nr, length_bits, length_len);

        p += length_len + nr;
    } else {
        /* check if there is enough space to put Length */
        length_len = 1 + stream_id_len + offset_len < dst_buf_len;
        CHECK_STREAM_SPACE(1 + stream_id_len + offset_len + length_len, dst_buf, dst_buf + dst_buf_len);
        vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;
        if (offset_len)
            vint_write(p, offset, offset_bits, offset_len);
        p += offset_len;
        if (length_len)
            *p++ = 0;
    }

    dst_buf[0] = 0x08
                 | (!!offset_len << 2)
                 | (!!length_len << 1)
                 | (!!fin << 0);
    return p - dst_buf;
}