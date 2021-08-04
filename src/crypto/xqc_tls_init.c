#include <openssl/ssl.h>
#include <openssl/err.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/crypto/xqc_tls_init.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_tls_0rtt.h"
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_transport_params.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_defs.h"

SSL_QUIC_METHOD xqc_ssl_quic_method;



#define XQC_SESSION_DEFAULT_TIMEOUT (7 * 24 * 60 * 60)

xqc_int_t
xqc_ssl_init_engine_config(xqc_engine_t *engine, const xqc_engine_ssl_config_t *src,
    xqc_ssl_session_ticket_key_t *session_ticket_key)
{
    xqc_engine_ssl_config_t *ssl_config = &engine->ssl_config;
    memset(ssl_config, 0, sizeof(xqc_engine_ssl_config_t));

    if (src->private_key_file != NULL && strlen(src->private_key_file) > 0) {
        int len = strlen(src->private_key_file);
        ssl_config->private_key_file = (char *)xqc_malloc(len + 1);
        strncpy(ssl_config->private_key_file, (const char *)(src->private_key_file), len);
        ssl_config->private_key_file[len] = '\0';

    } else {
        ssl_config->private_key_file = NULL;
    }

    if (src->cert_file != NULL &&  strlen(src->cert_file) > 0 ) {
        int len = strlen(src->cert_file);
        ssl_config->cert_file = (char *)xqc_malloc(len + 1);
        strncpy(ssl_config->cert_file, ( char *)(src->cert_file), len);
        ssl_config->cert_file[len] = '\0';

    } else {
        ssl_config->cert_file = NULL;
    }

    if (src->ciphers != NULL && strlen(src->ciphers) > 0 ) {
        int len = strlen(src->ciphers);
        ssl_config->ciphers = (char *)xqc_malloc(len + 1);
        strncpy(ssl_config->ciphers, (const char *)(src->ciphers), len);
        ssl_config->ciphers[len] = '\0';

    } else {
        int len = strlen(XQC_TLS_CIPHERS);
        ssl_config->ciphers = (char *)xqc_malloc(len + 1);
        strncpy(ssl_config->ciphers, XQC_TLS_CIPHERS, len);
        ssl_config->ciphers[len] = '\0';
    }

    if (src->groups != NULL && strlen(src->groups) > 0 ) {
        int len = strlen(src->groups);
        ssl_config->groups = (char *)xqc_malloc(len + 1);
        strncpy(ssl_config->groups, (const char *)(src->groups), len);
        ssl_config->groups[len] = '\0';

    } else {
        int len = strlen(XQC_TLS_GROUPS);
        ssl_config->groups = xqc_malloc(len + 1);
        strncpy(ssl_config->groups, XQC_TLS_GROUPS, len);
        ssl_config->groups[len] = '\0';
    }

    if (src->session_ticket_key_len > 0 ) {
        ssl_config->session_ticket_key_len = src->session_ticket_key_len;
        ssl_config->session_ticket_key_data  = (char *)xqc_malloc(src->session_ticket_key_len );
        memcpy(ssl_config->session_ticket_key_data, src->session_ticket_key_data, src->session_ticket_key_len);
        if (xqc_init_session_ticket_keys(session_ticket_key, ssl_config->session_ticket_key_data,
                                         ssl_config->session_ticket_key_len) < 0)
        {
            xqc_log(engine->log, XQC_LOG_ERROR, "|read session ticket key error|");
            return -XQC_TLS_INVALID_ARGUMENT;
        }

    } else {
        ssl_config->session_ticket_key_len = 0;
        ssl_config->session_ticket_key_data = NULL;
        if (engine->eng_type == XQC_ENGINE_SERVER) {
            xqc_log(engine->log, XQC_LOG_WARN, "|no session ticket key data|");
        }
    }

    if (src->alpn_list == NULL) {
        int len = strlen(XQC_ALPN_LIST);
        ssl_config->alpn_list = xqc_malloc(len + 1);
        strncpy(ssl_config->alpn_list, XQC_ALPN_LIST, len);
        ssl_config->alpn_list[len] = '\0';
        ssl_config->alpn_list_len = len;

    } else {
        ssl_config->alpn_list_len = src->alpn_list_len;
        ssl_config->alpn_list = (char *)xqc_malloc(src->alpn_list_len + 1);
        memcpy(ssl_config->alpn_list, src->alpn_list, src->alpn_list_len + 1);
        ssl_config->alpn_list[ssl_config->alpn_list_len] = '\0';
    }

    return XQC_OK;
}

xqc_int_t
xqc_ssl_init_conn_config(xqc_connection_t *conn, const xqc_conn_ssl_config_t *src, const char *alpn)
{
    xqc_conn_ssl_config_t * ssl_config = &(conn->tlsref.conn_ssl_config);
    memset(ssl_config, 0, sizeof(xqc_conn_ssl_config_t));
    if (src->session_ticket_len > 0) {
        ssl_config->session_ticket_len = src->session_ticket_len;
        ssl_config->session_ticket_data  = (char *)xqc_malloc(src->session_ticket_len + 1);
        if (ssl_config->session_ticket_data == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_malloc error|");
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        memcpy(ssl_config->session_ticket_data, src->session_ticket_data, src->session_ticket_len);
        ssl_config->session_ticket_data[src->session_ticket_len] = '\0';

    } else {
        ssl_config->session_ticket_len = 0;
        ssl_config->session_ticket_data = NULL;
        xqc_log(conn->log, XQC_LOG_WARN, "|no session ticket data|");
    }

    if (src->transport_parameter_data_len > 0) {
        ssl_config->transport_parameter_data_len = src->transport_parameter_data_len;
        ssl_config->transport_parameter_data  = (char *)xqc_malloc(src->transport_parameter_data_len + 1);
        if (ssl_config->transport_parameter_data == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_malloc error| ");
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        memcpy(ssl_config->transport_parameter_data, src->transport_parameter_data, src->transport_parameter_data_len);
        ssl_config->transport_parameter_data[src->transport_parameter_data_len] = '\0';

    } else {
        ssl_config->transport_parameter_data_len = 0;
        ssl_config->transport_parameter_data = NULL;
        xqc_log(conn->log, XQC_LOG_WARN, "|no transport parameter data|");
    }

    if (alpn == NULL) {
        conn->tlsref.alpn_num = XQC_ALPN_HTTP3_NUM;
    } else {
        if (strlen(alpn) == (sizeof(XQC_ALPN_HTTP3) - 1) && memcmp(alpn, XQC_ALPN_HTTP3, sizeof(XQC_ALPN_HTTP3) - 1) == 0) {
            conn->tlsref.alpn_num = XQC_ALPN_HTTP3_NUM;
        } else {
            conn->tlsref.alpn_num = XQC_ALPN_TRANSPORT_NUM;
        }
    }

    return XQC_OK;
}

static inline void
xqc_tlsref_zero(xqc_tlsref_t * tlsref)
{
    memset(tlsref, 0 , sizeof(xqc_tlsref_t));
}

/*
 * no_crypto_flag 0 means crypto, no_crypto_flag 1 means plain text 
 * return XQC_OK when success, return XQC_ERROR when error
 */
xqc_int_t
xqc_client_tls_initial(xqc_engine_t *engine, xqc_connection_t *conn,
    const char *hostname, const xqc_conn_ssl_config_t *sc, const char *alpn, 
    xqc_cid_t *dcid, uint16_t no_crypto_flag)
{
    xqc_int_t ret = XQC_ERROR;
    int ssl_rc = 0; /* for ssl return code */

    xqc_tlsref_t *tlsref = &conn->tlsref;
    xqc_tlsref_zero(tlsref);
    tlsref->conn = conn;
    tlsref->initial = 1;

    /* connection ssl config, early data flag should be initialled before call xqc_create_client_ssl */
    if (xqc_ssl_init_conn_config(conn, sc, alpn) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|initial conn config error |");
        return XQC_ERROR;
    }

    conn->xc_ssl = xqc_create_client_ssl(engine, conn, hostname, sc, alpn);
    if (conn->xc_ssl == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_client_ssl error |");
        return XQC_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    SSL_set_quic_use_legacy_codepoint(conn->xc_ssl, conn->version != XQC_VERSION_V1);
#else
    SSL_set_quic_transport_version(conn->xc_ssl, conn->version != XQC_VERSION_V1);
#endif

    xqc_init_list_head(&conn->tlsref.initial_pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.hs_pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.initial_pktns.msg_cb_buffer);
    xqc_init_list_head(&conn->tlsref.hs_pktns.msg_cb_buffer);
    xqc_init_list_head(&conn->tlsref.pktns.msg_cb_buffer);

    xqc_tls_callbacks_t *callbacks = &conn->tlsref.callbacks;
    callbacks->client_initial = xqc_client_initial_cb;
    callbacks->tls_recv_initial = NULL;
    callbacks->tls_recv_crypto_data = xqc_tls_recv_crypto_data_cb;
    callbacks->handshake_completed = xqc_handshake_completed_cb;
    callbacks->in_encrypt = xqc_do_hs_encrypt;
    callbacks->in_decrypt = xqc_do_hs_decrypt;
    callbacks->encrypt = xqc_do_encrypt;
    callbacks->decrypt = xqc_do_decrypt;
    callbacks->in_hp_mask = xqc_in_hp_mask_cb;
    callbacks->hp_mask = xqc_hp_mask_cb;
    callbacks->update_key = xqc_update_key;
    callbacks->recv_retry = xqc_tls_recv_retry_cb;

    tlsref->save_session_cb = engine->eng_callback.save_session_cb;
    tlsref->save_tp_cb = engine->eng_callback.save_tp_cb;
    tlsref->cert_verify_cb = engine->eng_callback.cert_verify_cb;

    xqc_trans_settings_t *settings = &conn->local_settings;
    if (no_crypto_flag == 1) {
        settings->no_crypto = XQC_TRUE;  /* no_crypto 1 means do not crypto*/

    } else {
        settings->no_crypto = XQC_FALSE;
    }

    const unsigned char *out;
    size_t outlen;
    ret = xqc_serialize_client_transport_params(conn,
            XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &out, &outlen);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|serialize client transport params error|");
        return XQC_ERROR;
    }

    ssl_rc = SSL_set_quic_transport_params(conn->xc_ssl, out, outlen);
    xqc_transport_parames_serialization_free((void*)out);
    if (ssl_rc != XQC_SSL_SUCCESS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|set client transport params error|");
        return XQC_ERROR;
    }

    xqc_conn_ssl_config_t *config = &conn->tlsref.conn_ssl_config;
    if ((config->transport_parameter_data_len > 0) 
        && (config->transport_parameter_data != NULL))
    {
        xqc_transport_params_t params;
        memset(&params, 0, sizeof(xqc_transport_params_t));
        if (xqc_read_transport_params(config->transport_parameter_data,
                    config->transport_parameter_data_len, &params) == XQC_OK)
        {
            ret = xqc_conn_set_early_remote_transport_params(conn, &params);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_DEBUG, 
                        "|set early remote transport params failed|error_code:%d|", ret);
            }

        } else {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|read transport params failed|");
        }
    }

    if (xqc_client_setup_initial_crypto_context(conn, dcid) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|error setup initial crypto key|");
        return XQC_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_server_tls_initial(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_engine_ssl_config_t *sc)
{
    xqc_tlsref_t *tlsref = &conn->tlsref;
    xqc_tlsref_zero(tlsref);

    tlsref->conn = conn;
    tlsref->initial = 1;
    tlsref->alpn_num = XQC_ALPN_DEFAULT_NUM;
    conn->xc_ssl = xqc_create_ssl(engine, conn, XQC_SERVER);
    if (conn->xc_ssl == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create ssl error|");
        return XQC_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    SSL_set_early_data_enabled(conn->xc_ssl, 1); 
#else
    SSL_set_quic_early_data_enabled(conn->xc_ssl, 1); /* enable 0rtt */
#endif

    SSL_set_quic_early_data_context(conn->xc_ssl, (const uint8_t *)XQC_EARLY_DATA_CONTEXT, 
                                    XQC_EARLY_DATA_CONTEXT_LEN);

    xqc_init_list_head(&conn->tlsref.initial_pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.hs_pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.pktns.msg_cb_head);
    xqc_init_list_head(&conn->tlsref.initial_pktns.msg_cb_buffer);
    xqc_init_list_head(&conn->tlsref.hs_pktns.msg_cb_buffer);
    xqc_init_list_head(&conn->tlsref.pktns.msg_cb_buffer);

    xqc_tls_callbacks_t *callbacks = &conn->tlsref.callbacks;
    callbacks->client_initial = NULL;
    callbacks->tls_recv_initial = xqc_tls_recv_initial_cb;
    callbacks->tls_recv_crypto_data = xqc_tls_recv_crypto_data_cb;
    callbacks->handshake_completed = xqc_handshake_completed_cb;
    callbacks->in_encrypt = xqc_do_hs_encrypt;
    callbacks->in_decrypt = xqc_do_hs_decrypt;
    callbacks->encrypt = xqc_do_encrypt;
    callbacks->decrypt = xqc_do_decrypt;
    callbacks->in_hp_mask = xqc_in_hp_mask_cb;
    callbacks->hp_mask = xqc_hp_mask_cb;
    callbacks->update_key = xqc_update_key;   /* update key */

    const unsigned char *out;
    size_t outlen;
    int rv = xqc_serialize_server_transport_params(conn,
            XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &out, &outlen);
    if (rv != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|serialize server transport params error|");
        return XQC_ERROR;
    }

    rv = SSL_set_quic_transport_params(conn->xc_ssl, out, outlen);
    xqc_transport_parames_serialization_free((void*)out);
    if (rv != XQC_SSL_SUCCESS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|set server transport params error|");
        return XQC_ERROR;
    }

    return XQC_OK;
}


#define XQC_MAX_VERIFY_DEPTH 100  /* the default max depth of cert chain is 100 */
#define XQC_TLS_SELF_SIGNED_CERT(err_code)  (err_code == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT || err_code == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
static int
xqc_cert_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    int i = 0, err_code = 0, ssl_rc = 0;
    size_t certs_array_len = 0;
    unsigned char *certs_array[XQC_MAX_VERIFY_DEPTH]={0};
    size_t certs_len[XQC_MAX_VERIFY_DEPTH]={0};

    if (preverify_ok == XQC_SSL_SUCCESS) {
        return preverify_ok;
    }

    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(ssl);
    if ((ssl == NULL) || (conn == NULL)) {
        if (conn) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|certificate verify failed because ssl NULL|");
            XQC_CONN_ERR(conn, TRA_HS_CERTIFICATE_VERIFY_FAIL);
        }
        return preverify_ok;
    }

    err_code = X509_STORE_CTX_get_error(ctx);
    if (err_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        && err_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        && !((conn->tlsref.cert_verify_flag & XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED) != 0
             && XQC_TLS_SELF_SIGNED_CERT(err_code)))
    {
        /* other err_code should log */
        xqc_log(conn->log, XQC_LOG_ERROR, "|certificate verify failed with err_code:%d|", err_code);
        XQC_CONN_ERR(conn, TRA_HS_CERTIFICATE_VERIFY_FAIL);

        preverify_ok = XQC_SSL_FAIL;
        return preverify_ok;
    }

#ifdef OPENSSL_IS_BORINGSSL
    const STACK_OF(CRYPTO_BUFFER) *chain = SSL_get0_peer_certificates(ssl);

    certs_array_len = sk_CRYPTO_BUFFER_num(chain);
    if (certs_array_len > XQC_MAX_VERIFY_DEPTH) {
        preverify_ok = XQC_SSL_FAIL;

        err_code = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err_code);

        return preverify_ok;
    }

    for (i = 0; i < certs_array_len; i++) {
        CRYPTO_BUFFER * buffer = sk_CRYPTO_BUFFER_value(chain, i);
        certs_array[i] = (unsigned char *)CRYPTO_BUFFER_data(buffer);
        certs_len[i] = (size_t)CRYPTO_BUFFER_len(buffer);
    }

#else 
    unsigned char *cert_buf = NULL;
    X509 *cert = NULL;
    int cert_size = 0;
    const STACK_OF(X509) *chain = X509_STORE_CTX_get_chain(ctx);

    certs_array_len = sk_X509_num(chain);
    if (certs_array_len > XQC_MAX_VERIFY_DEPTH) { /* imposible */
        preverify_ok = XQC_SSL_FAIL;

        err_code = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err_code);

        return preverify_ok;
    }

    for (i = 0; i < certs_array_len; i++) {
        cert = sk_X509_value(chain, i);

        cert_size = i2d_X509(cert, NULL);
        if (cert_size <= 0) {
            preverify_ok = XQC_SSL_FAIL;
            break;
        }

        /* remember to free memory before return */
        certs_array[i] = xqc_malloc(cert_size);
        if (certs_array[i] == NULL) {
            preverify_ok = XQC_SSL_FAIL;
            break;
        }
        cert_buf = certs_array[i];
        cert_size = i2d_X509(cert, &cert_buf);  /* this function modify cert_buf inside, use temp variable */
        if (cert_size <= 0) {
            preverify_ok = XQC_SSL_FAIL;
            break;
        }
        certs_len[i] = cert_size;

        xqc_log(conn->log, XQC_LOG_DEBUG, "|i=%d|cert_size=%d|", i, cert_size);
    }
#endif

    if (conn->tlsref.cert_verify_cb != NULL) {
        if (conn->tlsref.cert_verify_cb((const unsigned char **)certs_array, certs_len, 
                                        certs_array_len, xqc_conn_get_user_data(conn)) < 0) 
        {
            preverify_ok = XQC_SSL_FAIL;

        } else {
            preverify_ok = XQC_SSL_SUCCESS;
        }
    }

#ifndef OPENSSL_IS_BORINGSSL
    for (i = 0; i < certs_array_len; i++) {
        if(certs_array[i] != NULL) {
            xqc_free(certs_array[i]);
        }
    }
#endif
    return preverify_ok;
}


static void
xqc_ssl_ctx_set_timeout(SSL_CTX *ssl_ctx, const xqc_engine_ssl_config_t *xs_config)
{
    if (xs_config->session_timeout != 0) {
        SSL_CTX_set_timeout(ssl_ctx, xs_config->session_timeout);
#ifdef OPENSSL_IS_BORINGSSL
        SSL_CTX_set_session_psk_dhe_timeout(ssl_ctx, xs_config->session_timeout);
#endif
    } else {
        SSL_CTX_set_timeout(ssl_ctx, XQC_SESSION_DEFAULT_TIMEOUT);
#ifdef OPENSSL_IS_BORINGSSL
        SSL_CTX_set_session_psk_dhe_timeout(ssl_ctx, XQC_SESSION_DEFAULT_TIMEOUT);
#endif
    }
}

SSL_CTX *
xqc_create_client_ssl_ctx(xqc_engine_t *engine, const xqc_engine_ssl_config_t *xs_config)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION); //todo: get from config file if needed
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    if (SSL_CTX_set1_curves_list(ssl_ctx, xs_config->groups) != XQC_SSL_SUCCESS) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|", 
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    SSL_CTX_set_session_cache_mode(
            ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl_ctx, xqc_new_session_cb);

    xqc_ssl_ctx_set_timeout(ssl_ctx, xs_config);

    return ssl_ctx;
}


/**
 * create ssl_ctx for ssl
 * @return SSL_CTX, if error return null
 */
SSL_CTX *
xqc_create_server_ssl_ctx(xqc_engine_t *engine, const xqc_engine_ssl_config_t *xs_config)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    long ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        | SSL_OP_SINGLE_ECDH_USE
    #ifdef SSL_OP_NO_ANTI_REPLAY
        | SSL_OP_NO_ANTI_REPLAY
    #endif
        ;

    SSL_CTX_set_options(ssl_ctx, ssl_opts);

    if (SSL_CTX_set1_curves_list(ssl_ctx, xs_config->groups) != XQC_SSL_SUCCESS) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    SSL_CTX_set_alpn_select_cb(ssl_ctx, xqc_alpn_select_proto_cb, (void *)&(engine->ssl_config));

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, xs_config->private_key_file,
                SSL_FILETYPE_PEM) != XQC_SSL_SUCCESS) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, xs_config->cert_file) != XQC_SSL_SUCCESS) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != XQC_SSL_SUCCESS) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_check_private_key| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

#ifndef OPENSSL_IS_BORINGSSL
    /* The max_early_data parameter specifies the maximum amount of early data in bytes
     * that is permitted to be sent on a single connection
     */
    SSL_CTX_set_max_early_data(ssl_ctx, XQC_UINT32_MAX);
#endif
    if (xs_config -> session_ticket_key_len == 0 || xs_config -> session_ticket_key_data == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, "|read ssl session ticket key error|");

    } else {
        SSL_CTX_set_tlsext_ticket_key_cb(ssl_ctx, xqc_ssl_session_ticket_key_callback);
    }

    xqc_ssl_ctx_set_timeout(ssl_ctx, xs_config);

    return ssl_ctx;

fail:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}


SSL *
xqc_create_ssl(xqc_engine_t *engine, xqc_connection_t *conn, int flag)
{
    SSL *ssl = SSL_new((SSL_CTX *)engine->ssl_ctx);
    if (ssl == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|SSL_new return null|");
        return NULL;
    }

    SSL_set_app_data(ssl, conn);

    SSL_set_quic_method(ssl, &xqc_ssl_quic_method);

    if (flag == XQC_CLIENT) {
        SSL_set_connect_state(ssl);

    } else {
        SSL_set_accept_state(ssl);
    }

    return ssl;
}


/* never called, only for callback */
int
xqc_bio_write(BIO *b, const char *buf, int len)
{
    return -1;
}

int
xqc_bio_read(BIO *b, char *buf, int len)
{
    BIO_clear_retry_flags(b);
    xqc_connection_t * conn = (xqc_connection_t *) BIO_get_data(b);
    xqc_hs_buffer_t * p_buff = conn->tlsref.hs_to_tls_buf;
    if (p_buff == NULL) {
        BIO_set_retry_read(b);
        return -1;
    }

    if (p_buff->data_len > len) {
        return 0;
    }
    memcpy(buf, p_buff->data, p_buff->data_len);
    int ret_len = p_buff->data_len;

    xqc_free(conn->tlsref.hs_to_tls_buf);
    conn->tlsref.hs_to_tls_buf = NULL;

    if (ret_len == 0) {
        BIO_set_retry_read(b);
        return -1;
    }
    return ret_len;
}


int
xqc_client_bio_read(BIO *b, char *buf, int len)
{
    /* read client handshake data */
    return xqc_bio_read(b, buf, len);
}

int
xqc_server_bio_read(BIO *b, char *buf, int len)
{
    /* read server handshake data */
    return xqc_bio_read(b, buf, len);
}

int
xqc_bio_puts(BIO *b, const char *str)
{
    return xqc_bio_write(b, str, strlen(str));
}

int
xqc_bio_gets(BIO *b, char *buf, int len)
{
    return -1;
}

long
xqc_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_FLUSH:
        return 1;
    }

    return 0;
}

int
xqc_bio_create(BIO *b)
{
    /* do creat bio, when handle initialed will be called */
    BIO_set_init(b, 1);
    return 1;
}

int
xqc_bio_destroy(BIO *b)
{
    if (b == nullptr) {
        return 0;
    }

    return 1;
}

BIO_METHOD *
xqc_create_bio_method()
{
    /* just create bio for openssl */
    BIO_METHOD * meth = BIO_meth_new(BIO_TYPE_FD, "ssl_fd_bio");
    if (meth == NULL) {
        return NULL;
    }

    BIO_meth_set_write(meth, xqc_bio_write);
    BIO_meth_set_read(meth, xqc_bio_read);
    BIO_meth_set_puts(meth, xqc_bio_puts);
    BIO_meth_set_gets(meth, xqc_bio_gets);
    BIO_meth_set_ctrl(meth, xqc_bio_ctrl);
    BIO_meth_set_create(meth, xqc_bio_create);
    BIO_meth_set_destroy(meth, xqc_bio_destroy);
    return meth;
}

xqc_int_t
xqc_set_alpn_proto(SSL *ssl, const char *alpn)
{
    if (NULL == alpn) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    size_t alpn_len = strlen(alpn);
    if (alpn_len >= 128) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    /* 
     * ALPN protocol is a series of non-empty, 8-bit length-prefixed strings, 
     * the length is one byte more than input alpn string.
     */
    size_t protos_len = alpn_len + 1;
    uint8_t * p_alpn = xqc_malloc(protos_len + 1);
    if (p_alpn == NULL) {
        return -XQC_TLS_NOBUF;
    }

    /*
     * copy the alpn string len into first byte, copy the alpn string into
     * the rest bytes, set the last byte with '\0'
     */
    p_alpn[0] = alpn_len;
    strncpy(&p_alpn[1], alpn, protos_len);
    p_alpn[protos_len] = '\0';
    SSL_set_alpn_protos(ssl, p_alpn, protos_len);

    xqc_free(p_alpn);
    return XQC_OK;
}

SSL *
xqc_create_client_ssl(xqc_engine_t *engine, xqc_connection_t *conn,
    const char *hostname, const xqc_conn_ssl_config_t *sc, const char *alpn)
{
    SSL *ssl = xqc_create_ssl(engine, conn, XQC_CLIENT);
    if (ssl == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_client_ssl|create ssl error|");
        return NULL;
    }

    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    if (xqc_numeric_host(hostname)) {
        SSL_set_tlsext_host_name(ssl, "localhost");  //SNI need finish

    } else {
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    if (xqc_set_alpn_proto(ssl, alpn) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_client_ssl|set alpn error|");
        return NULL;
    }

    conn->tlsref.resumption = XQC_FALSE;
    if (sc->session_ticket_data && sc->session_ticket_len > 0) {
        if (xqc_read_session_data(ssl, conn, sc->session_ticket_data, sc->session_ticket_len) == XQC_OK) {
            conn->tlsref.resumption = XQC_TRUE;
#ifdef OPENSSL_IS_BORINGSSL
            SSL_set_early_data_enabled(ssl, 1); 
#else
            SSL_set_quic_early_data_enabled(ssl, 1);
#endif
        }
    }

    if (sc->cert_verify_flag & XQC_TLS_CERT_FLAG_NEED_VERIFY) { 

        conn->tlsref.cert_verify_flag = sc->cert_verify_flag;

        if (X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), hostname, strlen(hostname)) != XQC_SSL_SUCCESS) {
            xqc_log(conn->log,  XQC_LOG_DEBUG, "|centificate verify set hostname failed|");  /* hostname set failed need log */
        }
        SSL_set_verify(ssl, SSL_VERIFY_PEER, xqc_cert_verify_callback);
    }

    return ssl;
}

xqc_int_t
xqc_client_setup_initial_crypto_context(xqc_connection_t *conn, xqc_cid_t *dcid)
{
    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN] = { 0 };
    uint8_t secret[INITIAL_SECRET_MAX_LEN] = { 0 };
    int rv = xqc_derive_initial_secret(initial_secret, sizeof(initial_secret), dcid,
                                       (const uint8_t*)(xqc_crypto_initial_salt[conn->version]),
                                       strlen(xqc_crypto_initial_salt[conn->version]));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive initial secret failed|");
        return -XQC_TLS_NOKEY;
    }

    xqc_init_initial_crypto_ctx(conn);

    rv = xqc_derive_client_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive client initial secret failed|");
        return -XQC_TLS_NOKEY;
    }

    char key[16], iv[16], hp[16];
    ssize_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet protection key failed|");
        return -XQC_TLS_NOKEY;
    }

    ssize_t ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet protection iv failed|");
        return -XQC_TLS_NOKEY;
    }

    ssize_t hplen = xqc_derive_header_protection_key(
                hp, sizeof(hp), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet header protection key failed|");
        return -XQC_TLS_NOKEY;
    }

    if (xqc_conn_install_initial_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|install initial tx  key failed|");
        return -XQC_TLS_FATAL;
    }

    rv = xqc_derive_server_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive server initial secret failed|");
        return -XQC_TLS_NOKEY;
    }

    keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet protection key failed|");
        return -XQC_TLS_NOKEY;
    }

    ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet protection iv failed|");
        return -XQC_TLS_NOKEY;
    }

    hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive packet header protection key failed|");
        return -XQC_TLS_NOKEY;
    }

    if (xqc_conn_install_initial_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|install initial key error|");
        return -XQC_TLS_FATAL;
    }

    return XQC_OK;
}


xqc_int_t
xqc_set_cipher_suites(xqc_engine_t * engine)
{
    if (engine->ssl_ctx 
        && engine->ssl_config.ciphers && strlen(engine->ssl_config.ciphers) > 0)
    {
#ifndef OPENSSL_IS_BORINGSSL
        if (XQC_SSL_SUCCESS != SSL_CTX_set_ciphersuites(engine->ssl_ctx, engine->ssl_config.ciphers)) {
            xqc_log(engine->log, XQC_LOG_ERROR, 
                    "|SSL_CTX_set_ciphersuites failed|error info:%s|ciphers:%s|", 
                    ERR_error_string(ERR_get_error(), NULL), engine->ssl_config.ciphers);
            return -XQC_TLS_SET_CIPHER_SUITES_ERROR;
        }
#endif
    /* boringssl have a built-in preference order 
       and do not support setting TLS 1.3 cipher */
    }

    xqc_log(engine->log, XQC_LOG_DEBUG,
            "|set cipheer suites suc|ciphers:%s|", engine->ssl_config.ciphers);

    return XQC_OK;
}



void
xqc_keylog_cb(const SSL *ssl, const char *line)
{
    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(ssl);
    xqc_engine_t *eng = conn->engine;

    /* invoke engine's callback */
    if (eng->eng_callback.keylog_cb) {
        eng->eng_callback.keylog_cb(line, eng->user_data);
    }
}


void
xqc_set_keylog(xqc_engine_t *engine)
{
#ifdef XQC_PRINT_SECRET
    if (engine->eng_callback.keylog_cb) {
        SSL_CTX_set_keylog_callback(engine->ssl_ctx, xqc_keylog_cb);
    }
#endif
}
