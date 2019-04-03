
#ifndef _XQC_STREAM_H_INCLUDED_
#define _XQC_STREAM_H_INCLUDED_

#include "xqc_conn.h"
#include "../include/xquic_typedef.h"
#include "../include/xquic.h"
#include "xqc_frame.h"

typedef enum {
    XQC_CLI_BID = 0,
    XQC_SVR_BID = 1,
    XQC_CLI_UNI = 2,
    XQC_SVR_UNI = 3,
} xqc_stream_id_type_t;


typedef enum {
    XQC_SF_READY_TO_WRITE   = 1 << 0,
    XQC_SF_READY_TO_READ    = 1 << 1,
} xqc_stream_flag_t;


TAILQ_HEAD(xqc_stream_frame_tailq, xqc_stream_frame_t);
typedef struct xqc_stream_frame_tailq xqc_stream_frame_tailq_t;


/* Put all STREAM data here */
typedef struct xqc_stream_data_in_s {
    /* A list of STREAM frame, order by offset */
    xqc_stream_frame_tailq_t        frames_tailq;
    unsigned                        frames_num;
    uint64_t                        stream_length;
    unsigned char                   fin_received;
    unsigned char                   all_received;
} xqc_stream_data_in_t;


struct xqc_stream_s {
    xqc_connection_t        *stream_conn;
    xqc_stream_id_t         stream_id;
    xqc_stream_id_type_t    stream_id_type;
    uint64_t                stream_send_offset;
    TAILQ_ENTRY(xqc_stream_s)
                            next_write_stream,
                            next_read_stream;
    void                    *user_data;
    xqc_stream_callbacks_t  *stream_if;
    xqc_stream_flag_t       stream_flag;

    xqc_stream_data_in_t    stream_data_in;
};

void
xqc_process_write_streams (xqc_connection_t *conn);

void
xqc_process_read_streams (xqc_connection_t *conn);

void
xqc_process_crypto_write_streams (xqc_connection_t *conn);

void
xqc_process_crypto_read_streams (xqc_connection_t *conn);

void
xqc_stream_ready_to_write (xqc_stream_t *stream);

void
xqc_stream_shutdown_write (xqc_stream_t *stream);

void
xqc_stream_ready_to_read (xqc_stream_t *stream);

void
xqc_stream_shutdown_read (xqc_stream_t *stream);

xqc_stream_t *
xqc_find_stream_by_id (xqc_stream_id_t stream_id, xqc_id_hash_table_t *streams_hash);

xqc_stream_t *
xqc_create_crypto_stream (xqc_connection_t *conn,
                          void *user_data);

#endif /* _XQC_STREAM_H_INCLUDED_ */

