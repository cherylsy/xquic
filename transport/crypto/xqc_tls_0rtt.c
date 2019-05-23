#include "xqc_tls_0rtt.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "xqc_tls_init.h"
#include "xqc_tls_cb.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"
#include "include/xquic_typedef.h"

xqc_ssl_session_ticket_key_t g_session_ticket_key; // only one session ticket key ,need finish

int xqc_get_session_file_path(char * session_path, const char * hostname, char * filename, int size){

    if(strlen(hostname) <= 0 ){
        return -1;
    }
    snprintf(filename, size, "%s/%s",session_path, hostname);
    return 0;
}


int xqc_get_tp_path( char * path, const char * hostname, char * filename, int size){
    if(strlen(path) <= 0){
        return -1;
    }
    snprintf(filename, size, "%s/tp_%s", path, hostname);
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
                SSL_SESSION_free(session);
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
        //?return -1;
    }
#if 0
    int name_type = SSL_get_servername_type(ssl);
    if(name_type == -1){
        printf("Could not write TLS session in %s \n", sc->session_path);
        return -1;
    }
    const char * fn = SSL_get_servername(ssl, name_type);
#endif
    char * fn = conn->tlsref.hostname;
    char filename[512];
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


int xqc_ssl_session_ticket_keys(SSL_CTX *ctx ,  xqc_ssl_session_ticket_key_t * key ,char * path  ){

    (void *)ctx;
    memset(key, 0, sizeof(xqc_ssl_session_ticket_key_t));
    if(path == NULL){
        return -1;
    }
    FILE * fp = fopen(path, "r");

    size_t size;
    char buf[256];

    if (fp == NULL){
        return -1;
    }

    fseek(fp, 0, SEEK_END);

    size = ftell(fp);

    fseek(fp, 0, SEEK_SET);

    if(size != 48 && size != 80){
        printf("session key size is not 48 or 80\n");
        fclose(fp);
        return -1;
    }
    int n = fread(buf, 1, size, fp);
    if(n != size){
        printf("session key size is not 48 or 80\n");
        fclose(fp);
        return -1;

    }

    if (size == 48) {
        key->size = 48;
        memcpy(key->name, buf, 16);
        memcpy(key->aes_key, buf + 16, 16);
        memcpy(key->hmac_key, buf + 32, 16);

    } else {
        key->size = 80;
        memcpy(key->name, buf, 16);
        memcpy(key->hmac_key, buf + 16, 32);
        memcpy(key->aes_key, buf + 48, 32);
    }

    return 0;
}

int xqc_ssl_session_ticket_key_callback(SSL *s, unsigned char *name,
        unsigned char *iv,
        EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc){
    size_t size;
    const EVP_MD                  *digest;
    const EVP_CIPHER              *cipher;

    digest = EVP_sha256();

    xqc_ssl_session_ticket_key_t *key = &g_session_ticket_key;

    if (enc == 1) {
        /* encrypt session ticket */
        if (key->size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            printf("RAND_bytes() failed\n");
            return -1;
        }
        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key->aes_key, iv) != 1) {
            printf("EVP_EncryptInit_ex() failed\n");
            return -1;
        }

        if (HMAC_Init_ex(hctx, key->hmac_key, size, digest, NULL) != 1) {
            printf("HMAC_Init_ex() failed \n");
            return -1;
        }

        memcpy(name, key->name, 16);
        return 1;
    }else{
        /* decrypt session ticket */
        if(memcmp(name, key->name, 16) != 0){

            printf("ssl session ticket decrypt, key not match\n");
            return 0;
        }
        if (key -> size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (HMAC_Init_ex(hctx, key->hmac_key, size, digest, NULL) != 1) {
            printf("HMAC_Init_ex() failed\n");
            return -1;
        }

        if (EVP_DecryptInit_ex(ectx, cipher, NULL, key->aes_key, iv) != 1) {
            printf("EVP_DecryptInit_ex() failed");
            return -1;
        }
        return 1;

    }

}

