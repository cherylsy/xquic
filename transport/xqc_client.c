#include "xqc_client.h"
#include "../include/xquic.h"
#include "xqc_transport.h"
#include "xqc_cid.h"


int 
xqc_connect(xqc_client_connection_t *client_conn, 
                xqc_engine_t *engine, void *user_data) 
{
    int ret = XQC_ERROR;
    xqc_cid_t dcid;
    xqc_cid_t scid;
    xqc_conn_callbacks_t callbacks;

    if (xqc_generate_cid(engine, &scid) != XQC_OK
        || xqc_generate_cid(engine, &dcid) != XQC_OK) 
    {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|generate dcid or scid error|");
        goto fail;
    }

    client_conn->xc = xqc_client_create_connection(engine, dcid, scid, 
                    &callbacks, engine->settings, user_data);

    if (client_conn->xc == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|create connection error|");
        goto fail;
    }

    return XQC_OK;

fail:
    ret = XQC_ERROR;
    return ret;
}

