#include "xqc_client.h"
#include "../include/xquic.h"
#include "xqc_transport.h"
#include "xqc_cid.h"



xqc_cid_t *
xqc_connect(xqc_engine_t *engine, void *user_data, unsigned char *token, unsigned token_len, char *server_host, int no_crypto_flag, uint8_t no_early_data_flag, xqc_conn_ssl_config_t * conn_ssl_config )
{
    xqc_cid_t dcid;
    xqc_cid_t scid;
    xqc_conn_callbacks_t callbacks = engine->eng_callback.conn_callbacks;

    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|exceed XQC_MAX_TOKEN_LEN|");
        return NULL;
    }

    if (xqc_generate_cid(engine, &scid) != XQC_OK
        || xqc_generate_cid(engine, &dcid) != XQC_OK)
    {
        xqc_log(engine->log, XQC_LOG_WARN,
                        "|generate dcid or scid error|");
        goto fail;
    }

    //TODO: for test
    memset(scid.cid_buf, 0xCC, 4);
    memset(dcid.cid_buf, 0xDD, dcid.cid_len);

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid,
                    &callbacks, &engine->conn_settings, server_host, no_crypto_flag, no_early_data_flag, conn_ssl_config, user_data);

    if (xc == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN,
                        "|create connection error|");
        goto fail;
    }

    if (token && token_len > 0) {
        xc->conn_token_len = token_len;
        memcpy(xc->conn_token, token, token_len);
    }

    xqc_log(engine->log, XQC_LOG_DEBUG,
            "|xqc_connect|");

    if (xc->conn_callbacks.conn_create_notify) {
        if (xc->conn_callbacks.conn_create_notify(&xc->scid, user_data)) {
            xqc_destroy_connection(xc);
            goto fail;
        }
    }

    if (engine->event_timer) {
        xqc_engine_main_logic(engine);
    }

    return &xc->scid;

fail:
    return NULL;
}




