
#include "xqc_cid.h"
#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_random.h"

xqc_int_t 
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid)
{
    cid->cid_len = 8; /* TODO: input length */
    if (xqc_get_random(&engine->rand_generator, cid->cid_buf, cid->cid_len) != XQC_OK) {
        return XQC_ERROR;
    }   

    return XQC_OK;
}

