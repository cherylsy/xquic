#ifndef _XQC_TRANSPORT_H_INCLUDED_
#define _XQC_TRANSPORT_H_INCLUDED_

#include <stdint.h>
#include "../common/xqc_common.h"
#include "../common/xqc_memory_pool.h"
#include "../common/xqc_id_hash.h"
#include "../common/xqc_time.h"
#include "../common/xqc_log.h"
#include "../common/xqc_buf.h"

typedef enum
{
    TRA_NO_ERROR                   =  0x0,
    TRA_INTERNAL_ERROR             =  0x1,
    TRA_SERVER_BUSY                =  0x2,
    TRA_FLOW_CONTROL_ERROR         =  0x3,
    TRA_STREAM_LIMIT_ERROR         =  0x4,
    TRA_STREAM_STATE_ERROR         =  0x5,
    TRA_FINAL_SIZE_ERROR           =  0x6,
    TRA_FRAME_ENCODING_ERROR       =  0x7,
    TRA_TRANSPORT_PARAMETER_ERROR  =  0x8,
    TRA_VERSION_NEGOTIATION_ERROR  =  0x9,
    TRA_PROTOCOL_VIOLATION         =  0xA,
    TRA_INVALID_MIGRATION          =  0xC,
} xqc_trans_error_code;


#endif /* _XQC_TRANSPORT_H_INCLUDED_ */

