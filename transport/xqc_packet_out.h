
#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include "../common/xqc_types.h"

typedef struct xqc_packet_out_s
{
    unsigned char           *po_buf;
    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    xqc_packet_number_t     po_pktno;

} xqc_packet_out_t;

#endif //_XQC_PACKET_OUT_H_INCLUDED_
