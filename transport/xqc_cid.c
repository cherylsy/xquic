
#include "xqc_cid.h"
#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_random.h"

xqc_int_t 
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid)
{
    if (xqc_get_random(engine, (u_char *)&cid->cid, sizeof(uint64_t)) != XQC_OK) {
        return XQC_ERROR;
    }   

    return XQC_OK;
}

