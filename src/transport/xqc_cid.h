
#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include <xquic/xquic_typedef.h>


#define XQC_DEFAULT_CID_LEN 8

xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid, uint64_t cid_seq_num);

void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_init_zero(xqc_cid_t *cid);
void xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len);

#endif /* _XQC_CID_H_INCLUDED_ */

