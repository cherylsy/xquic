#ifndef _XQC_TLS_0RTT_H_INCLUDE_
#define _XQC_TLS_0RTT_H_INCLUDE_

#include <openssl/ssl.h>
#include "src/crypto/xqc_tls_public.h"


int xqc_get_session_file_path(char * session_path, const char * hostname, char * filename, int size);

int xqc_get_tp_path( char * path, const char * hostname, char * filename, int size);

int xqc_read_session( SSL * ssl, xqc_connection_t *conn, char * filename);

int xqc_new_session_cb(SSL *ssl, SSL_SESSION *session) ;

int xqc_read_session_data( SSL * ssl, xqc_connection_t *conn, char * session_data, size_t session_data_len);

int xqc_ssl_session_ticket_keys(SSL_CTX *ctx ,  xqc_ssl_session_ticket_key_t * key ,char * path );

int xqc_ssl_session_ticket_key_callback(SSL *s, unsigned char key_name[16],
        unsigned char iv[EVP_MAX_IV_LENGTH],
        EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc);
int xqc_init_session_ticket_keys(xqc_ssl_session_ticket_key_t * key, char * session_key_data, size_t session_key_len);
int xqc_set_early_data_cb(xqc_connection_t * conn, xqc_early_data_cb_t  early_data_cb);

#endif
