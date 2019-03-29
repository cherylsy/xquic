
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

typedef struct xqc_packet_s {
    xqc_packet_number_t     pkt_num;
    xqc_pkt_num_space_t     pkt_pns;
    xqc_pkt_type_t          pkt_type;
    xqc_cid_t               pkt_dcid;
}xqc_packet_t;

#endif //_XQC_PACKET_H_INCLUDED_
