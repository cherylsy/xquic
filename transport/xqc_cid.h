
#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include "../include/xquic_typedef.h"
#include "../common/xqc_common.h"
#include "../common/xqc_str.h"

#define XQC_DEFAULT_CID_LEN 8

xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid);

xqc_int_t xqc_cid_is_equal(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_init_zero(xqc_cid_t *cid);
void xqc_cid_set(xqc_cid_t *cid, unsigned char *data, size_t len);


#endif /* _XQC_CID_H_INCLUDED_ */

