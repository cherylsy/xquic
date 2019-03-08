
#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_


static int gen_stream_frame (unsigned char *dst_buf, size_t dst_buf_len,
                  xqc_stream_id_t stream_id, uint64_t offset, int fin, size_t size,
                  gsf_read_f gsf_read, void *stream);

#endif //_XQC_FRAME_PARSER_H_INCLUDED_
