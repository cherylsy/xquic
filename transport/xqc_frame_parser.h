
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include "../common/xqc_types.h"

/**
 * generate stream frame
 * @param written_size output size of the payload been written
 * @return size of stream frame
 */
int xqc_gen_stream_frame(unsigned char *dst_buf, size_t dst_buf_len,
                         xqc_stream_id_t stream_id, size_t offset, int fin_only,
                         const unsigned char *payload, size_t size, size_t *written_size);


#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
