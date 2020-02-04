#include "xqc_tls_0rtt.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "http3/xqc_h3_conn.h"
#include "xqc_tls_init.h"
#include "xqc_tls_cb.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"
#include "include/xquic_typedef.h"
#include "transport/xqc_engine.h"

xqc_ssl_session_ticket_key_t g_session_ticket_key; // only one session ticket key ,need finish

int xqc_get_session_file_path(char * session_path, const char * hostname, char * filename, int size)
{

    if(strlen(hostname) <= 0 ){
        return -1;
    }
    snprintf(filename, size, "%s/%s",session_path, hostname);
    return 0;
}


int xqc_get_tp_path( char * path, const char * hostname, char * filename, int size)
{
    if(strlen(path) <= 0){
        return -1;
    }
    snprintf(filename, size, "%s/tp_%s", path, hostname);
    return 0;
}


/*
 *@result : 0 means session timeout, 1 means session is not timeout
 */
int xqc_tls_check_session_ticket_timeout(SSL_SESSION * session)
{
    uint32_t now = (uint32_t)time(NULL);
    uint32_t session_time = SSL_get_time(session);
    if(session_time > now){
        return 0;
    }

    uint32_t agesec = now - session_time;
    uint64_t session_timeout = SSL_SESSION_get_timeout(session); //session->ext.tick_lifetime_hint same as session->timeout
    if(session_timeout < agesec){
        return 0;
    }
    return 1; //means session do not timeout
}


int xqc_read_session_data( SSL * ssl, xqc_connection_t *conn, char * session_data, size_t session_data_len)
{
    BIO * m_f = BIO_new_mem_buf(session_data, session_data_len);
    if(m_f == NULL){
        xqc_log(conn->log, XQC_LOG_DEBUG, "| xqc_read_session_data | new mem buf error |");
        return -1;
    }

    int ret = 0;
    SSL_SESSION * session = PEM_read_bio_SSL_SESSION(m_f, NULL, 0, NULL);

    if(session == NULL){
        ret = -1;
        xqc_log(conn->log, XQC_LOG_DEBUG, "| xqc_read_session_data | read session ticket info error |");
        goto end;
    }else{
        if(xqc_tls_check_session_ticket_timeout(session) == 0){
            ret = -1;
            xqc_log(conn->log, XQC_LOG_DEBUG, "| xqc_read_session_data | session timeout |");
            goto end;
        }
        if (!SSL_set_session(ssl, session)) {
            ret = -1;
            xqc_log(conn->log, XQC_LOG_DEBUG, "| xqc_read_session_data | set session error |");
            goto end;
        }else{
            ret = 0;
            goto end;
        }
    }

end:
    if(m_f)BIO_free(m_f);
    if(session)SSL_SESSION_free(session); //free by referrence count
    return ret;
}


int xqc_read_session( SSL * ssl, xqc_connection_t *conn, char * filename)
{
    BIO * f = BIO_new_file(filename, "r");
    if (f == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|Could not read TLS session file %s\n|", filename);
        return -1;
    } else {
        SSL_SESSION * session = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
        BIO_free(f);
        if (session == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|Could not read TLS session file %s\n|", filename);
            return -1;
        } else {
            if (!SSL_set_session(ssl, session)) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|Could not set session  %s\n|", filename);
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

int xqc_set_save_session_cb(xqc_engine_t  *engine, xqc_cid_t *cid, xqc_save_session_cb_t  cb, void * user_data)
{
    xqc_connection_t * conn = xqc_engine_conns_hash_find(engine, cid, 's');
    conn->tlsref.save_session_cb = cb;
    conn->tlsref.session_user_data = user_data;
    return 0;
}

int xqc_set_save_tp_cb(xqc_engine_t *engine, xqc_cid_t * cid, xqc_save_tp_cb_t  cb, void * user_data)
{
    xqc_connection_t * conn = xqc_engine_conns_hash_find(engine, cid, 's');
    conn->tlsref.save_tp_cb = cb;
    conn->tlsref.tp_user_data = user_data;
    return 0;
}

int xqc_set_early_data_cb(xqc_connection_t * conn, xqc_early_data_cb_t  early_data_cb)
{
    conn->tlsref.early_data_cb = early_data_cb;
    return 0;
}



int xqc_new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(ssl);
    if (SSL_SESSION_get_max_early_data(session) != XQC_UINT32_MAX) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|max_early_data_size is not 0xffffffff|");
        return -1;
    }

    int ret = 0;
    if(conn->tlsref.save_session_cb != NULL){
        char *p_data = NULL;
        BIO * m_f = BIO_new(BIO_s_mem());
        if(m_f == NULL){
            xqc_log(conn->log, XQC_LOG_ERROR, "|save new session error|");
            return -1;
        }
        PEM_write_bio_SSL_SESSION(m_f, session);
        size_t data_len = BIO_get_mem_data(m_f,  &p_data);
        if(data_len == 0 || p_data == NULL){
            xqc_log(conn->log, XQC_LOG_ERROR, "|save new session  error|");
            ret = -1;
        }else{
            ret = conn->tlsref.save_session_cb(p_data, data_len, xqc_conn_get_user_data(conn));
        }
        BIO_free(m_f); //free
        return ret;
    }
    return ret;
}

int xqc_init_session_ticket_keys(xqc_ssl_session_ticket_key_t * key, char * session_key_data, size_t session_key_len)
{
    if(session_key_len != 48 && session_key_len != 80){
        return -1;
    }
    memset(key, 0, sizeof(xqc_ssl_session_ticket_key_t));
    if (session_key_len == 48) {
        key->size = 48;
        memcpy(key->name, session_key_data, 16);
        memcpy(key->aes_key, session_key_data + 16, 16);
        memcpy(key->hmac_key, session_key_data + 32, 16);
    } else {
        key->size = 80;
        memcpy(key->name, session_key_data, 16);
        memcpy(key->hmac_key, session_key_data + 16, 32);
        memcpy(key->aes_key, session_key_data + 48, 32);
    }

    return 0;
}


int xqc_ssl_session_ticket_key_callback(SSL *s, unsigned char *name,
        unsigned char *iv,
        EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
    size_t size;
    const EVP_MD                  *digest;
    const EVP_CIPHER              *cipher;

    digest = EVP_sha256();

    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(s);
    xqc_ssl_session_ticket_key_t *key = &(conn->engine->session_ticket_key);

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
            xqc_log(conn->log, XQC_LOG_ERROR, "|RAND_bytes() failed|");
            return -1;
        }
        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key->aes_key, iv) != 1) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|EVP_EncryptInit_ex() failed|");
            return -1;
        }

        if (HMAC_Init_ex(hctx, key->hmac_key, size, digest, NULL) != 1) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|HMAC_Init_ex() failed |");
            return -1;
        }

        memcpy(name, key->name, 16);
        return 1;
    }else{
        /* decrypt session ticket */
        if(memcmp(name, key->name, 16) != 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "|ssl session ticket decrypt, key not match|");
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
            xqc_log(conn->log, XQC_LOG_ERROR, "|HMAC_Init_ex() failed|");
            return -1;
        }

        if (EVP_DecryptInit_ex(ectx, cipher, NULL, key->aes_key, iv) != 1) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|EVP_DecryptInit_ex() failed|");
            return -1;
        }
        return 1;
    }
}

