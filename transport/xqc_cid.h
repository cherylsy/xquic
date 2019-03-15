
#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include "xqc_transport.h"

typedef struct {
    uint64_t cid;
}xqc_cid_t;


xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid);


#endif /* _XQC_CID_H_INCLUDED_ */

