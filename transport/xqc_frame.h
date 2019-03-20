#ifndef _XQC_FRAME_H_INCLUDED_
#define _XQC_FRAME_H_INCLUDED_

#include "../include/xquic_typedef.h"

unsigned int
xqc_stream_frame_header_size (xqc_stream_id_t stream_id, uint64_t offset, size_t length);

#endif /* _XQC_FRAME_H_INCLUDED_ */
