
#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "../common/xqc_common.h"

#define XQC_DEFAULT_CID_LEN 8

xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid);


#endif /* _XQC_CID_H_INCLUDED_ */

