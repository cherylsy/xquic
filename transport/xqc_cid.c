
#include "xqc_cid.h"
#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_random.h"

xqc_int_t 
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid)
{
    cid->cid_len = XQC_DEFAULT_CID_LEN; /* TODO: input length */
    if (xqc_get_random(engine->rand_generator, cid->cid_buf, cid->cid_len) != XQC_OK) {
        return XQC_ERROR;
    }   

    return XQC_OK;
}

void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src)
{
    dst->cid_len = src->cid_len;
    xqc_memcpy(dst->cid_buf, src->cid_buf, dst->cid_len);
}

void xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    xqc_memzero(cid->cid_buf, XQC_MAX_CID_LEN);
}

void xqc_cid_set(xqc_cid_t *cid, unsigned char *data, size_t len)
{
    cid->cid_len = len;
    xqc_memcpy(cid->cid_buf, data, len);
}

