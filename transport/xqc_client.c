#include "xqc_client.h"
#include "../include/xquic.h"
#include "xqc_transport.h"
#include "xqc_cid.h"



xqc_connection_t *
xqc_connect(xqc_engine_t *engine, void *user_data)
{
    int ret = XQC_ERROR;
    xqc_cid_t dcid;
    xqc_cid_t scid;
    xqc_conn_callbacks_t callbacks = engine->eng_callback.conn_callbacks;

    if (xqc_generate_cid(engine, &scid) != XQC_OK
        || xqc_generate_cid(engine, &dcid) != XQC_OK) 
    {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|generate dcid or scid error|");
        goto fail;
    }

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid,
                    &callbacks, engine->settings, user_data);

    if (xc == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|create connection error|");
        goto fail;
    }

    ret = xqc_crypto_stream_on_write(xc->crypto_stream[XQC_ENC_LEV_INIT], NULL);
    if (ret != XQC_OK) {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|xqc_crypto_stream_on_write error|");
        goto fail;
    }

    return xc;

fail:
    ret = XQC_ERROR;
    return NULL;
}

