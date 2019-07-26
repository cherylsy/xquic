
#ifndef _XQC_STREAM_H_INCLUDED_
#define _XQC_STREAM_H_INCLUDED_

#include "xqc_conn.h"
#include "../include/xquic_typedef.h"
#include "../include/xquic.h"
#include "xqc_frame.h"
#include "../common/xqc_list.h"
#include "xqc_packet.h"

typedef enum {
    XQC_CLI_BID = 0,
    XQC_SVR_BID = 1,
    XQC_CLI_UNI = 2,
    XQC_SVR_UNI = 3,
} xqc_stream_id_type_t;


typedef enum {
    XQC_SF_READY_TO_WRITE       = 1 << 0,
    XQC_SF_READY_TO_READ        = 1 << 1,
    XQC_SF_STREAM_DATA_BLOCKED  = 1 << 2,
} xqc_stream_flag_t;

typedef enum {
    XQC_SSS_READY,
    XQC_SSS_SEND,
    XQC_SSS_DATA_SENT,
    XQC_SSS_DATA_RECVD,
    XQC_SSS_RESET_SENT,
    XQC_SSS_RESET_RECVD,
} xqc_send_stream_state_t;

typedef enum {
    XQC_RSS_RECV,
    XQC_RSS_SIZE_KNOWN,
    XQC_RSS_DATA_RECVD,
    XQC_RSS_DATA_READ,
    XQC_RSS_RESET_RECVD,
    XQC_RSS_RESET_READ,
} xqc_recv_stream_state_t;

typedef struct {
    uint64_t                fc_max_stream_data;
} xqc_stream_flow_ctl_t;


/* Put one STREAM frame */
typedef struct xqc_stream_frame_s {
    xqc_list_head_t sf_list;
    unsigned char   *data;
    unsigned        data_length;
    uint64_t        data_offset;
    uint64_t        next_read_offset;   /* next offset in frame */
    unsigned char   fin;
} xqc_stream_frame_t;


/* Put all received STREAM data here */
typedef struct xqc_stream_data_in_s {
    /* A list of STREAM frame, order by offset */
    xqc_list_head_t         frames_tailq;       /* xqc_stream_frame_t */
    uint64_t                merged_offset_end;  /* [0,end) 收齐 */
    uint64_t                next_read_offset;   /* next offset in stream */
    uint64_t                stream_length;
} xqc_stream_data_in_t;


typedef struct xqc_stream_write_buff_s {
    xqc_list_head_t         sw_list;
    unsigned char           *sw_data;
    unsigned                data_length;
    uint64_t                data_offset;
    uint64_t                next_write_offset;
    unsigned char           fin;
} xqc_stream_write_buff_t;

typedef struct xqc_stream_write_buff_list_s {
    xqc_list_head_t         write_buff_list; /* xqc_stream_write_buff_t */
    uint64_t                next_write_offset;
    uint64_t                total_len;
} xqc_stream_write_buff_list_t;

struct xqc_stream_s {
    xqc_connection_t        *stream_conn;
    xqc_stream_id_t         stream_id;
    xqc_stream_id_type_t    stream_id_type;
    uint64_t                stream_send_offset;
    xqc_list_head_t         write_stream_list,
                            read_stream_list,
                            all_stream_list;
    void                    *user_data;
    xqc_stream_callbacks_t  *stream_if;
    xqc_stream_flag_t       stream_flag;
    xqc_encrypt_level_t     stream_encrypt_level;
    xqc_stream_data_in_t    stream_data_in;
    xqc_stream_write_buff_list_t
                            stream_write_buff_list;

    xqc_stream_flow_ctl_t   stream_flow_ctl;
    unsigned                stream_unacked_pkt;
    xqc_send_stream_state_t stream_state_send;
    xqc_recv_stream_state_t stream_state_recv;
};

xqc_stream_t *
xqc_create_stream_with_conn (xqc_connection_t *conn,
                             void *user_data);
void
xqc_destroy_stream(xqc_stream_t *stream);

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
xqc_server_create_stream (xqc_connection_t *conn, xqc_stream_id_t stream_id,
                          void *user_data);

xqc_stream_t *
xqc_create_crypto_stream (xqc_connection_t *conn,
                          xqc_encrypt_level_t encrypt_level,
                          void *user_data);

int
xqc_crypto_stream_on_write (xqc_stream_t *stream, void *user_data);

int xqc_read_crypto_stream(xqc_stream_t * stream);
ssize_t
xqc_stream_write_buff(xqc_stream_t *stream,
                      unsigned char *send_data,
                      size_t send_data_size,
                      uint8_t fin);

int
xqc_stream_write_buff_to_packets(xqc_stream_t *stream);

void
xqc_destroy_stream_frame(xqc_stream_frame_t *stream_frame);

void
xqc_destroy_write_buff(xqc_stream_write_buff_t *write_buff);

void
xqc_destroy_frame_list(xqc_list_head_t *head);

void
xqc_destroy_write_buff_list(xqc_list_head_t *head);

#endif /* _XQC_STREAM_H_INCLUDED_ */

