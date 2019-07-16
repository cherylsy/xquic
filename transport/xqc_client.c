#include "xqc_client.h"
#include "../include/xquic.h"
#include "xqc_transport.h"
#include "xqc_cid.h"



xqc_cid_t *
xqc_connect(xqc_engine_t *engine, void *user_data, unsigned char *token, unsigned token_len)
{
    xqc_cid_t dcid;
    xqc_cid_t scid;
    xqc_conn_callbacks_t callbacks = engine->eng_callback.conn_callbacks;

    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|xqc_connect|exceed XQC_MAX_TOKEN_LEN|");
        return NULL;
    }

    if (xqc_generate_cid(engine, &scid) != XQC_OK
        || xqc_generate_cid(engine, &dcid) != XQC_OK) 
    {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|generate dcid or scid error|");
        goto fail;
    }

    //TODO: for test
    memset(scid.cid_buf, 0xCC, 4);
    memset(dcid.cid_buf, 0xDD, dcid.cid_len);

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid,
                    &callbacks, engine->settings, user_data);

    if (xc == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, 
                        "|xqc_connect|create connection error|");
        goto fail;
    }

    if (token) {
        xc->conn_token_len = token_len;
        memcpy(xc->conn_token, token, token_len);
    }

    if (engine->event_timer) {
        xqc_engine_main_logic(engine);
    }

    return &xc->scid;

fail:
    return NULL;
}




