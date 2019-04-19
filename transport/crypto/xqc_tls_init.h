#ifndef _XQC_TLS_INIT_H_INCLUDED_
#define _XQC_TLS_INIT_H_INCLUDED_

#include <openssl/ssl.h>
#include "xqc_tls_public.h"

#ifndef nullptr
#define nullptr NULL
#endif

#define INITIAL_SECRET_MAX_LEN  32


int xqc_ssl_init_config(xqc_ssl_config_t *xsc, char *private_key_file, char *cert_file);

int xqc_tlsref_init(xqc_tlsref_t * tlsref); //initialize tlsref memory to zero

SSL_CTX *xqc_create_client_ssl_ctx(xqc_ssl_config_t *xs_config);

SSL_CTX * xqc_create_server_ssl_ctx(xqc_ssl_config_t *xs_config);


SSL * xqc_create_ssl(xqc_engine_t * engine, xqc_connection_t * conn, xqc_ssl_config_t *sc);

SSL * xqc_create_client_ssl(xqc_engine_t * engine, xqc_connection_t * conn, char * hostname, xqc_ssl_config_t * sc);

int xqc_client_setup_initial_crypto_context( xqc_connection_t *conn, xqc_cid_t *dcid );


#endif
