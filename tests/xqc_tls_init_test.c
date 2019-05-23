#include <CUnit/CUnit.h>
#include "string.h"
#include "xqc_tls_init.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"

void xqc_ssl_init_config_test(){

    xqc_ssl_config_t  xqc;
    char ciphers[] = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    char groups[] = "P-256:X25519:P-384:P-521";
    char p_key_file[] = "/usr/opt/keyfile";
    char cert_file[] = "/urs/opt/certfile";
    xqc_ssl_init_config(&xqc, p_key_file, cert_file, NULL);

    CU_ASSERT(0 == strcmp(xqc.ciphers, ciphers));
    CU_ASSERT(0 == strcmp(xqc.groups, groups));
    CU_ASSERT(0 == strcmp(xqc.private_key_file, p_key_file));
    CU_ASSERT(0 == strcmp(xqc.cert_file, cert_file));


}


void xqc_create_client_ssl_ctx_test(){
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    SSL_CTX * ssl_ctx = xqc_create_client_ssl_ctx(&xsc);

    CU_ASSERT( ssl_ctx != NULL);

}


void xqc_create_server_ssl_ctx_test(){
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    SSL_CTX * ssl_ctx = xqc_create_server_ssl_ctx(&xsc);

    CU_ASSERT( ssl_ctx != NULL);

}

void xqc_create_ssl_test(){
    xqc_engine_t engine;
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    engine.ssl_ctx = xqc_create_server_ssl_ctx(&xsc);
    CU_ASSERT( engine.ssl_ctx != NULL);

    xqc_connection_t conn;
    //SSL *ssl = xqc_create_ssl(&engine,  &conn, &xsc);

    //CU_ASSERT( ssl != NULL);
}


void xqc_create_client_ssl_test(){
    xqc_engine_t engine;
    xqc_ssl_config_t xsc;
    xqc_ssl_init_config(&xsc, "./keyfile", "./certfile", NULL);

    engine.ssl_ctx = xqc_create_client_ssl_ctx(&xsc);

    xqc_connection_t conn;
    SSL *ssl = xqc_create_client_ssl(&engine,  &conn, "127.0.0.1", &xsc);

    CU_ASSERT( ssl != NULL);
}







