#ifndef _XQC_TLS_0RTT_H_INCLUDE_
#define _XQC_TLS_0RTT_H_INCLUDE_

#include <openssl/ssl.h>
#include "xqc_tls_public.h"


int xqc_get_session_file_path(char * session_path, const char * hostname, char * filename, int size);


int xqc_read_session( SSL * ssl, xqc_connection_t *conn, char * filename);


int xqc_new_session_cb(SSL *ssl, SSL_SESSION *session) ;

#endif
