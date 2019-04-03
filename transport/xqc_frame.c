
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_variable_len_int.h"

unsigned int
xqc_stream_frame_header_size (xqc_stream_id_t stream_id, uint64_t offset, size_t length)
{
    return 1 + xqc_vint_len_by_val(stream_id) +
            offset ? xqc_vint_len_by_val(offset) : 0 +
            xqc_vint_len_by_val(length);

}

unsigned int
xqc_crypto_frame_header_size (uint64_t offset, size_t length)
{
    return 1 +
           xqc_vint_len_by_val(offset) +
           xqc_vint_len_by_val(length);

}