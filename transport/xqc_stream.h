
#ifndef _XQC_STREAM_H_INCLUDED_
#define _XQC_STREAM_H_INCLUDED_

#include "xqc_conn.h"
#include "xqc_transport.h"
#include "../common/xqc_types.h"

struct xqc_stream_s {
    xqc_connection_t    *stream_conn;
    xqc_stream_id_t     stream_id;
};

#endif /* _XQC_STREAM_H_INCLUDED_ */

