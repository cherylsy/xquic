#include "xqc_tls_init.h"
#include "xqc_client.h"
#include "include/xquic.h"
#include "xqc_transport.h"
#include "xqc_cid.h"
#include "xqc_conn.h"
#include "xqc_stream.h"

xqc_connection_t *
xqc_client_connect(xqc_engine_t *engine, void *user_data,
                   unsigned char *token, unsigned token_len,
                   char *server_host, int no_crypto_flag,
                   xqc_conn_ssl_config_t *conn_ssl_config)
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
    /*memset(scid.cid_buf, 0xCC, 4);
    memset(dcid.cid_buf, 0xDD, dcid.cid_len);*/

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid,
                                                        &callbacks, &engine->conn_settings, server_host,
                                                        no_crypto_flag, conn_ssl_config, user_data);

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
        if (xc->conn_callbacks.conn_create_notify(xc, &xc->scid, user_data)) {
            xqc_conn_destroy(xc);
            goto fail;
        }
        xc->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_engine_main_logic(engine);

    return xc;

fail:
    return NULL;
}

xqc_cid_t *
xqc_connect(xqc_engine_t *engine, void *user_data,
            unsigned char *token, unsigned token_len,
            char *server_host, int no_crypto_flag,
            xqc_conn_ssl_config_t *conn_ssl_config)
{
    xqc_connection_t *conn;
    conn = xqc_client_connect(engine, user_data, token, token_len,
                       server_host, no_crypto_flag, conn_ssl_config);
    if (conn) {
        return &conn->scid;
    }
    return NULL;
}

xqc_connection_t *
xqc_client_create_connection(xqc_engine_t *engine,
                             xqc_cid_t dcid, xqc_cid_t scid,
                             xqc_conn_callbacks_t *callbacks,
                             xqc_conn_settings_t *settings,
                             char * server_host,
                             int no_crypto_flag,
                             xqc_conn_ssl_config_t * conn_ssl_config,
                             void *user_data)
{
    xqc_connection_t *xc = xqc_conn_create(engine, &dcid, &scid,
                                                 callbacks, settings, user_data,
                                                 XQC_CONN_TYPE_CLIENT);

    if (xc == NULL) {
        return NULL;
    }

    if(xqc_client_tls_initial(engine, xc, server_host, conn_ssl_config, &dcid, no_crypto_flag) < 0 ){
        goto fail;
    }

    xqc_cid_copy(&(xc->ocid), &(xc->dcid));

    xc->cur_stream_id_bidi_local = 0;
    xc->cur_stream_id_uni_local = 2;

    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, XQC_ENC_LEV_INIT, user_data);
    if (!xc->crypto_stream[XQC_ENC_LEV_INIT]) {
        goto fail;
    }
    return xc;

    fail:
    xqc_conn_destroy(xc);
    return NULL;
}



