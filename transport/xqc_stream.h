
#ifndef _XQC_STREAM_H_INCLUDED_
#define _XQC_STREAM_H_INCLUDED_

#include "xqc_conn.h"
#include "../include/xquic_typedef.h"
#include "../include/xquic.h"

typedef enum {
    XQC_CLI_BID = 0,
    XQC_SVR_BID = 1,
    XQC_CLI_UNI = 2,
    XQC_SVR_UNI = 3,
} xqc_stream_id_type_t;

struct xqc_stream_s {
    xqc_connection_t        *stream_conn;
    xqc_stream_id_t         stream_id;
    xqc_stream_id_type_t    stream_id_type;
    uint64_t                stream_send_offset;
    TAILQ_ENTRY(xqc_stream_s)
                            next_write_stream,
                            next_read_stream;
    void                    *user_data;
    xqc_engine_callback_t   *stream_if;
};

void
xqc_process_write_streams (xqc_connection_t *conn);

void
xqc_process_read_streams (xqc_connection_t *conn);

#endif /* _XQC_STREAM_H_INCLUDED_ */

