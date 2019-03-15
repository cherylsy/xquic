
#ifndef _XQC_TYPES_H_INCLUDED_
#define _XQC_TYPES_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#define XQC_MAX_CID_LEN 18

typedef uint64_t xqc_packet_number_t;

typedef uint64_t xqc_stream_id_t;

typedef struct
{
    uint8_t    cid_len;
    uint8_t    cid_buf[XQC_MAX_CID_LEN];
} xqc_cid_t;

#endif /*_XQC_TYPES_H_INCLUDED_*/
