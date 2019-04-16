
#ifndef _XQC_PACKET_H_INCLUDED_
#define _XQC_PACKET_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "../common/xqc_list.h"

typedef enum xqc_pkt_num_space
{
    XQC_PNS_INIT = 0,
    XQC_PNS_HSK = 1,
    XQC_PNS_01RTT = 2,
    XQC_PNS_N = 3,
} xqc_pkt_num_space_t;

typedef enum xqc_encrypt_level
{
    XQC_ENC_LEV_INIT = 0,
    XQC_ENC_LEV_0RTT = 1,
    XQC_ENC_LEV_HSK = 2,
    XQC_ENC_LEV_1RTT = 3,
    XQC_ENC_MAX_LEVEL = 4,
} xqc_encrypt_level_t;

typedef enum xqc_pkt_type
{
    XQC_PTYPE_INIT  = 0,
    XQC_PTYPE_0RTT  = 1,
    XQC_PTYPE_HSK   = 2,
    XQC_PTYPE_RETRY = 3,
    XQC_PTYPE_SHORT_HEADER,
    XQC_PTYPE_VERSION_NEGOTIATION,
} xqc_pkt_type_t;


#define XQC_PACKET_TYPE_INIT       0
#define XQC_PACKET_TYPE_0RTT       1
#define XQC_PACKET_TYPE_HANDSHAKE  2
#define XQC_PACKET_TYPE_RETRY      3

#define XQC_PACKET_0RTT_MAX_COUNT  100

struct xqc_packet_s {
    xqc_packet_number_t     pkt_num;
    xqc_pkt_num_space_t     pkt_pns;
    xqc_pkt_type_t          pkt_type;
    xqc_cid_t               pkt_dcid;
    xqc_cid_t               pkt_scid;
};

typedef struct xqc_pktno_range_s {
    xqc_packet_number_t low, high;
} xqc_pktno_range_t;

typedef struct xqc_pktno_range_node_s {
    xqc_pktno_range_t   pktno_range;
    xqc_list_head_t     list;
} xqc_pktno_range_node_t;

typedef struct xqc_recv_record_s {
    xqc_list_head_t         list_head; //xqc_pktno_range_node_t
    xqc_msec_t              largest_pkt_recv_time;
    xqc_packet_number_t     rr_del_from;
} xqc_recv_record_t;

typedef struct xqc_ack_info_s {
    xqc_pkt_num_space_t     pns;
    unsigned                n_ranges;  /* must > 0 */
    xqc_pktno_range_t       ranges[64];
    xqc_msec_t              ack_delay;
} xqc_ack_info_t;

#define XQC_PACKET_IS_LONG_HEADER(buf) ((buf[0] & 0x80) != 0)
#define XQC_PACKET_IS_SHORT_HEADER(buf) ((buf[0] & 0x80) == 0)

#define XQC_PACKET_LONG_HEADER_GET_DCIL(buf) ((buf[0] & 0xF0) >> 4)
#define XQC_PACKET_LONG_HEADER_GET_SCIL(buf) ((buf[0] & 0x0F))

#define XQC_PACKET_VERSION_LENGTH 4
#define XQC_PACKET_LONG_HEADER_PREFIX_LENGTH (1 + XQC_PACKET_VERSION_LENGTH + 1)
#define XQC_PACKET_INITIAL_MIN_LENGTH   1200


#define xqc_parse_uint16(p) ((p)[0] << 8 | (p)[1])
#define xqc_parse_uint32(p) ((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])


xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                             unsigned char *buf, size_t size);

xqc_int_t xqc_conn_process_packets(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in);

typedef enum
{
    XQC_PKTRANGE_OK,
    XQC_PKTRANGE_DUP,
    XQC_PKTRANGE_ERR,
} xqc_pkt_range_status;

void xqc_recv_record_del (xqc_recv_record_t *recv_record, xqc_packet_number_t del_from);

xqc_pkt_range_status xqc_recv_record_add (xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number,
                                          xqc_msec_t recv_time);

xqc_packet_number_t xqc_recv_record_largest(xqc_recv_record_t *recv_record);

void xqc_maybe_should_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns, int out_of_order, xqc_msec_t now);

#endif //_XQC_PACKET_H_INCLUDED_
