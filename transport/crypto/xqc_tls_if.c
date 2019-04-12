#include "xqc_tls_if.h"


/*
 *call ssl to generate handshake data
 *@return 0 means success
 */
int xqc_tls_handshake(xqc_connection_t *conn){
    ERR_clear_error();
    int rv = SSL_do_handshake(conn->ssl_);
    if( rv <= 0){
        int err = SSL_get_error(ssl_, rv);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
                printf("TLS handshake error: %s \n", ERR_error_string(ERR_get_error(), nullptr));
                return -1;
            default:
                printf("TLS handshake error\n");
                return -1;
        }
    }

    xqc_conn_handshake_completed(conn);
    return 0;

}



