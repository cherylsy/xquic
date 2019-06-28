
#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "xqc_packet.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_frame.h"

#define XQC_PACKET_OUT_SIZE 1280    //TODO 先写死

#define XQC_MAX_STREAM_FRAME_IN_PO 3

typedef enum {
    XQC_POF_IN_FLIGHT        = 1 << 0,
} xqc_packet_out_flag_t;

typedef struct xqc_po_stream_frame_s {
    xqc_stream_t            *ps_stream;
    unsigned char           ps_has_fin; /* stream frame是否带fin */
    unsigned char           ps_is_reset; /* 是否是RESET STREAM frame */
} xqc_po_stream_frame_t;

typedef struct xqc_packet_out_s
{
    xqc_packet_t            po_pkt;
    xqc_list_head_t         po_list;
    unsigned char           *po_buf;
    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    xqc_packet_out_flag_t   po_flag;
    unsigned char           *ppktno;
    /* Largest Acknowledged in ACK frame, if there is no ACK frame, it should be 0 */
    xqc_packet_number_t     po_largest_ack;
    xqc_msec_t              po_sent_time;
    xqc_frame_type_bit_t    po_frame_types;
    /* stream frame 关联的stream */
    xqc_po_stream_frame_t   po_stream_frames[XQC_MAX_STREAM_FRAME_IN_PO];
} xqc_packet_out_t;

xqc_packet_out_t *
xqc_create_packet_out (xqc_send_ctl_t *ctl, enum xqc_pkt_type pkt_type);

void
xqc_destroy_packet_out(xqc_packet_out_t *packet_out);

void
xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

xqc_packet_out_t*
xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type);

xqc_packet_out_t*
xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need);

int
xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

int
xqc_should_generate_ack(xqc_connection_t *conn);

int
xqc_write_ack_to_packets(xqc_connection_t *conn);

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

int
xqc_write_conn_close_to_packet(xqc_connection_t *conn, unsigned short err_code);

int
xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 unsigned short err_code, uint64_t final_size);

int
xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 unsigned short err_code);

int
xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit);

int
xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

int
xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional);

int
xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data);

int
xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t max_stream_data);

int
xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional);



#endif //_XQC_PACKET_OUT_H_INCLUDED_
