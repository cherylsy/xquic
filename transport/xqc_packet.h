
#ifndef _XQC_PACKET_H_INCLUDED_
#define _XQC_PACKET_H_INCLUDED_

#include "../include/xquic_typedef.h"

typedef enum xqc_pkt_num_space
{
    PNS_INIT,
    PNS_HSK,
    PNS_01RTT,
} xqc_pkt_num_space_t;

typedef enum xqc_pkt_type
{
    PTYPE_INIT  = 0,
    PTYPE_0RTT  = 1,
    PTYPE_HSK   = 2,
    PTYPE_RETRY = 3,
    PTYPE_SHORT_HEADER,
    PTYPE_VER,
} xqc_pkt_type_t;

struct xqc_packet_s {
    xqc_packet_number_t     pkt_num;
    xqc_pkt_num_space_t     pkt_pns;
    xqc_pkt_type_t          pkt_type;
    xqc_cid_t               pkt_dcid;
};


#define XQC_PACKET_IS_LONG_HEADER(buf) ((buf[0] & 0x80) != 0)
#define XQC_PACKET_IS_SHORT_HEADER(buf) ((buf[0] & 0x80) == 0)

#define XQC_PACKET_LONG_HEADER_GET_DCIL(buf) ((buf[0] & 0xF0) >> 4)
#define XQC_PACKET_LONG_HEADER_GET_SCIL(buf) ((buf[0] & 0x0F))

#define XQC_PACKET_VERSION_LENGTH 4
#define XQC_PACKET_LONG_HEADER_PREFIX_LENGTH (1 + XQC_PACKET_VERSION_LENGTH + 1)

xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                             unsigned char *buf, size_t size);

xqc_int_t xqc_conn_process_packets(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in);


#endif //_XQC_PACKET_H_INCLUDED_
