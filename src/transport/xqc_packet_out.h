
#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_frame.h"

/*
 * https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-14.1
   In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP
   packets larger than 1280 bytes.  Assuming the minimum IP header size,
   this results in a QUIC maximum packet size of 1232 bytes for IPv6 and
   1252 bytes for IPv4.  A QUIC implementation MAY be more conservative
   in computing the QUIC maximum packet size to allow for unknown tunnel
   overheads or IP header options/extensions.
 */
#define XQC_PACKET_OUT_SIZE 1200    //不含XQC_EXTRA_SPACE XQC_ACK_SPACE
#define XQC_EXTRA_SPACE XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_ACK_SPACE 16
#define XQC_PACKET_OUT_SIZE_EXT (XQC_PACKET_OUT_SIZE + XQC_EXTRA_SPACE + XQC_ACK_SPACE)

#define XQC_MAX_STREAM_FRAME_IN_PO 3

typedef enum {
    XQC_POF_IN_FLIGHT        = 1 << 0,
    XQC_POF_LOST             = 1 << 1,
    XQC_POF_DCID_NOT_DONE    = 1 << 2,
    XQC_POF_ENCRYPTED        = 1 << 3,
    XQC_POF_TLP              = 1 << 4,
    XQC_POF_STREAM_UNACK     = 1 << 5,
    XQC_POF_NO_RETRANS       = 1 << 6,
    XQC_POF_STREAM_CLOSED    = 1 << 7,
} xqc_packet_out_flag_t;

typedef struct xqc_po_stream_frame_s {
    xqc_stream_id_t         ps_stream_id;
    unsigned char           ps_is_used;
    unsigned char           ps_has_fin; /* stream frame是否带fin */
    unsigned char           ps_is_reset; /* 是否是RESET STREAM frame */
} xqc_po_stream_frame_t;

typedef struct xqc_packet_out_s {
    xqc_packet_t            po_pkt;
    xqc_list_head_t         po_list;

    /* pointers should carefully assign in xqc_packet_out_copy */
    unsigned char          *po_buf;
    unsigned char          *po_ppktno;
    unsigned char          *po_payload;
    xqc_packet_out_t       *po_origin;          /* point to original packet before retransmitted */
    void                   *po_ping_user_data;  /* 上层用于区别哪个ping被ack */

    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    xqc_packet_out_flag_t   po_flag;
    /* Largest Acknowledged in ACK frame, if there is no ACK frame, it should be 0 */
    xqc_packet_number_t     po_largest_ack;
    xqc_msec_t              po_sent_time;
    xqc_frame_type_bit_t    po_frame_types;
    /* stream frame 关联的stream */
    xqc_po_stream_frame_t   po_stream_frames[XQC_MAX_STREAM_FRAME_IN_PO];
    uint32_t                po_origin_ref_cnt;  /* reference count of original packet */
    uint32_t                po_acked;
    uint64_t                po_delivered;       /* 在发送packet P之前已经标记为发送完毕的数据量 */
    xqc_msec_t              po_delivered_time;  /* 在发送packet P之前最后一个被ack的包的时间 */
    xqc_msec_t              po_first_sent_time; /* 当前采样周期中第一个packet的发送时间 */
    unsigned char           po_is_app_limited;
    void                    *ping_user_data; /* 上层用于区别哪个ping被ack */

    /*For BBRv2*/
    uint64_t po_tx_in_flight; /*the inflight bytes when the packet is sent (including itself)*/
    uint32_t po_lost; /*how many packets have been lost when the packet is sent*/
} xqc_packet_out_t;

xqc_packet_out_t *
xqc_packet_out_create();

void
xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src);

xqc_packet_out_t *
xqc_packet_out_get(xqc_send_ctl_t *ctl, enum xqc_pkt_type pkt_type);

void
xqc_packet_out_destroy(xqc_packet_out_t *packet_out);

void
xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

xqc_packet_out_t*
xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type);

xqc_packet_out_t*
xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need);

int
xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

int
xqc_write_ack_to_packets(xqc_connection_t *conn);

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

int
xqc_write_ping_to_packet(xqc_connection_t *conn, void *user_data);

int
xqc_write_conn_close_to_packet(xqc_connection_t *conn, uint64_t err_code);

int
xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 uint64_t err_code, uint64_t final_size);

int
xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 uint64_t err_code);

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

int
xqc_write_new_token_to_packet(xqc_connection_t *conn);

int
xqc_write_stream_frame_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 xqc_pkt_type_t pkt_type, uint8_t fin,
                                 const unsigned char *payload, size_t payload_size, size_t *send_data_written);

int
xqc_write_handshake_done_frame_to_packet(xqc_connection_t *conn);


#endif //_XQC_PACKET_OUT_H_INCLUDED_
