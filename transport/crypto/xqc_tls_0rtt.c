#include "xqc_tls_0rtt.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "xqc_tls_init.h"
#include "xqc_tls_cb.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"
#include "include/xquic_typedef.h"




int xqc_get_session_file_path(char * session_path, const char * hostname, char * filename, int size){

    if(strlen(hostname) <= 0 ){
        return -1;
    }
    snprintf(filename, size, "%s/%s",session_path, hostname);
    return 0;
}



int xqc_read_session( SSL * ssl, xqc_connection_t *conn, char * filename){
    BIO * f = BIO_new_file(filename, "r");
    if (f == NULL) {
        printf("Could not read TLS session file %s\n", filename);
        return -1;
    } else {
        SSL_SESSION * session = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
        BIO_free(f);
        if (session == NULL) {
            printf("Could not read TLS session file %s\n", filename);
                return -1;
        } else {
            if (!SSL_set_session(ssl, session)) {
                printf("Could not set session %s\n", filename);
                return -1;
            } else {
                SSL_SESSION_free(session);
                return 0;
            }
        }
    }
    return -1;

}

int xqc_new_session_cb(SSL *ssl, SSL_SESSION *session) {
    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(ssl);
    xqc_ssl_config_t *sc  = conn->tlsref.sc;
    if (SSL_SESSION_get_max_early_data(session) != XQC_UINT32_MAX) {
        printf("max_early_data_size is not 0xffffffff\n");
    }
    int name_type = SSL_get_servername_type(ssl);
    if(name_type == -1){
        printf("Could not write TLS session in %s \n", sc->session_path);
        return -1;
    }
    char filename[512];
    const char * fn = SSL_get_servername(ssl, name_type);
    if(xqc_get_session_file_path(sc->session_path, fn, filename, sizeof(filename) ) < 0){
        printf("Could not write TLS session in %s \n", sc->session_path);
        return -1;
    }
    BIO * f = BIO_new_file(filename, "w");
    if (f == NULL) {
        printf("Could not write TLS session in %s \n", filename);
        return 0;
    }

    PEM_write_bio_SSL_SESSION(f, session);
    BIO_free(f);

    return 0;
}



