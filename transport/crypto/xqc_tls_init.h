#ifndef _XQC_TLS_INIT_H_INCLUDED_
#define _XQC_TLS_INIT_H_INCLUDED_

#include <openssl/ssl.h>
#include "xqc_tls_public.h"
#include "include/xquic.h"

#ifndef nullptr
#define nullptr NULL
#endif

#define INITIAL_SECRET_MAX_LEN  32
int xqc_ssl_init_engine_config(xqc_engine_t *engine, xqc_engine_ssl_config_t * src , xqc_ssl_session_ticket_key_t * session_ticket_key);
int xqc_ssl_init_conn_config(xqc_connection_t * conn, xqc_conn_ssl_config_t * src);

int xqc_tlsref_init(xqc_tlsref_t * tlsref); //initialize tlsref memory to zero

SSL_CTX *xqc_create_client_ssl_ctx(xqc_engine_t * engine, xqc_engine_ssl_config_t *xs_config);

SSL_CTX * xqc_create_server_ssl_ctx(xqc_engine_t * engine, xqc_engine_ssl_config_t *xs_config);


SSL * xqc_create_ssl(xqc_engine_t * engine, xqc_connection_t * conn, int flag);

SSL * xqc_create_client_ssl(xqc_engine_t * engine, xqc_connection_t * conn, char * hostname, xqc_conn_ssl_config_t * conn_ssl_config );

int xqc_client_setup_initial_crypto_context( xqc_connection_t *conn, xqc_cid_t *dcid );

int xqc_client_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, char * hostname,  xqc_conn_ssl_config_t * conn_ssl_config,  xqc_cid_t *dcid, uint16_t no_crypto_flag);
int xqc_server_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, xqc_engine_ssl_config_t *sc);


#endif
