#include "xqc_tls_cb_test.h"
#include <CUnit/CUnit.h>
#include "string.h"
#include "xqc_tls_init.h"
#include "xqc_tls_cb.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"

void xqc_tls_key_cb_test(){
    xqc_engine_t engine;
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    engine.ssl_ctx = xqc_create_client_ssl_ctx(&xsc);

    xqc_connection_t conn;

    xqc_tlsref_init(&conn.tlsref);

    SSL *ssl = xqc_create_client_ssl(&engine,  &conn, "127.0.0.1", &xsc);

    char secret[32] = "123456789012345678901234567890";
    size_t secret_len = strlen(secret);
    int rc = xqc_tls_key_cb(ssl, SSL_KEY_SERVER_HANDSHAKE_TRAFFIC, secret, secret_len, &conn);

    CU_ASSERT( rc == 0);
    CU_ASSERT(conn.tlsref.crypto_ctx.prf != NULL);
    CU_ASSERT(conn.tlsref.crypto_ctx.aead != NULL);

}


void xqc_alpn_select_proto_cb_test(){
    xqc_engine_t engine;
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    engine.ssl_ctx = xqc_create_server_ssl_ctx(&xsc);

    xqc_connection_t conn;

    xqc_tlsref_init(&conn.tlsref);
    SSL *ssl = xqc_create_client_ssl(&engine,  &conn, "127.0.0.1", &xsc);

    conn.version = XQC_QUIC_VERSION;

    const unsigned char **out;
    char *out_len;
    int rc = xqc_alpn_select_proto_cb(ssl, out, out_len, NULL, 0, NULL );
    CU_ASSERT(rc  == SSL_TLSEXT_ERR_OK);

}
