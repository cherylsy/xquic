#ifndef _XQC_TLS_INIT_H_INCLUDED_
#define _XQC_TLS_INIT_H_INCLUDED_

#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include "src/crypto/xqc_tls_public.h"

#ifndef nullptr
#define nullptr NULL
#endif


xqc_int_t xqc_ssl_init_engine_config(xqc_engine_t *engine, const xqc_engine_ssl_config_t *src,
    xqc_ssl_session_ticket_key_t *session_ticket_key);

xqc_int_t xqc_ssl_init_conn_config(xqc_connection_t *conn, const xqc_conn_ssl_config_t *src, const char *alpn);

xqc_int_t xqc_tlsref_init(xqc_tlsref_t * tlsref); //initialize tlsref memory to zero

SSL_CTX *xqc_create_client_ssl_ctx(xqc_engine_t *engine, const xqc_engine_ssl_config_t *xs_config);

SSL_CTX *xqc_create_server_ssl_ctx(xqc_engine_t *engine, const xqc_engine_ssl_config_t *xs_config);

SSL *xqc_create_ssl(xqc_engine_t *engine, xqc_connection_t *conn, int flag);

SSL *xqc_create_client_ssl(xqc_engine_t *engine, xqc_connection_t *conn,
    const char *hostname, const xqc_conn_ssl_config_t *conn_ssl_config, const char *alpn);

xqc_int_t xqc_client_setup_initial_crypto_context(xqc_connection_t *conn, xqc_cid_t *dcid);

xqc_int_t xqc_client_tls_initial(xqc_engine_t *engine, xqc_connection_t *conn,
    const char *hostname, const xqc_conn_ssl_config_t *conn_ssl_config, const char *alpn, xqc_cid_t *dcid, uint16_t no_crypto_flag);

xqc_int_t xqc_server_tls_initial(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_engine_ssl_config_t *sc);

BIO_METHOD *xqc_create_bio_method();

xqc_int_t xqc_set_cipher_suites(xqc_engine_t *engine);

void xqc_set_keylog(xqc_engine_t *engine);

#endif
