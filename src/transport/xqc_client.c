#include <xquic/xquic.h>
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_defs.h"

xqc_connection_t *
xqc_client_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const char *alpn, 
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    xqc_cid_t dcid;
    xqc_cid_t scid;

    if (NULL == conn_ssl_config) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|xqc_conn_ssl_config is NULL|");
        return NULL;
    }

    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|%ud exceed XQC_MAX_TOKEN_LEN|", token_len);
        return NULL;
    }

    if (xqc_generate_cid(engine, NULL, &scid, 0) != XQC_OK
        || xqc_generate_cid(engine, NULL, &dcid, 0) != XQC_OK)
    {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|generate dcid or scid error|");
        return NULL;
    }

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid, conn_settings,
                                                        server_host, no_crypto_flag,
                                                        conn_ssl_config, alpn, user_data);
    if (xc == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|create connection error|");
        return NULL;
    }

    if (token && token_len > 0) {
        xc->conn_token_len = token_len;
        memcpy(xc->conn_token, token, token_len);
    }

    if (peer_addr && peer_addrlen > 0) {
        xc->peer_addrlen = peer_addrlen;
        memcpy(xc->peer_addr, peer_addr, peer_addrlen);
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|xqc_connect|");
    xqc_log_event(xc->log, CON_CONNECTION_STARTED, xc, XQC_LOG_REMOTE_EVENT);

    /* conn_create callback */
    if (xc->app_proto_cbs.conn_cbs.conn_create_notify) {
        if (xc->app_proto_cbs.conn_cbs.conn_create_notify(xc, &xc->scid_set.user_scid, user_data)) {
            xqc_conn_destroy(xc);
            return NULL;
        }

        xc->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    /* xqc_conn_destroy must be called before the connection is inserted into conns_active_pq */
    if (!(xc->conn_flag & XQC_CONN_FLAG_TICKING)){
        if (xqc_conns_pq_push(engine->conns_active_pq, xc, 0)) {
            return NULL;
        }
        xc->conn_flag |= XQC_CONN_FLAG_TICKING;
    }

    xqc_engine_main_logic_internal(engine, xc);

    /* when the connection is destroyed in the main logic, we should return error to upper level */
    if (xqc_engine_conns_hash_find(engine, &scid, 's') == NULL) {
        return NULL;
    }

    return xc;
}

const xqc_cid_t *
xqc_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, const char *alpn, void *user_data)
{
    xqc_connection_t *conn;

    if (NULL == alpn) {
        return NULL;
    }

    conn = xqc_client_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag, 
                              conn_ssl_config, alpn, peer_addr, peer_addrlen, user_data);
    if (conn) {
        return &conn->scid_set.user_scid;
    }

    return NULL;
}

xqc_connection_t *
xqc_client_create_connection(xqc_engine_t *engine,
    xqc_cid_t dcid, xqc_cid_t scid,
    const xqc_conn_settings_t *settings,
    const char * server_host,
    int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const char *alpn,
    void *user_data)
{
    xqc_connection_t *xc = xqc_conn_create(engine, &dcid, &scid, settings, user_data,
                                           XQC_CONN_TYPE_CLIENT);
    if (xc == NULL) {
        return NULL;
    }

    if (xqc_client_tls_initial(engine, xc, server_host, conn_ssl_config, alpn, &dcid, no_crypto_flag) < 0) {
        goto fail;
    }

    xqc_cid_copy(&(xc->original_dcid), &(xc->dcid_set.current_dcid));

    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, XQC_ENC_LEV_INIT, user_data);
    if (!xc->crypto_stream[XQC_ENC_LEV_INIT]) {
        goto fail;
    }

    if (xqc_conn_client_on_alpn(xc, alpn, strlen(alpn)) != XQC_OK) {
        goto fail;
    }

    return xc;

fail:
    xqc_conn_destroy(xc);
    return NULL;
}

