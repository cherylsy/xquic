
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
    PTYPE_SHORT_HEADER,
    PTYPE_VER,
    PTYPE_INIT,
    PTYPE_0RTT,
    PTYPE_HSK,
    PTYPE_RETRY,
} xqc_pkt_type_t;

typedef struct xqc_packet_s {
    xqc_packet_number_t     pkt_num;
    xqc_pkt_num_space_t     pkt_pns;
    xqc_pkt_type_t          pkt_type;

    uint64_t                pkt_recv_time;  /* millisecond */
}xqc_packet_t;

#endif //_XQC_PACKET_H_INCLUDED_
