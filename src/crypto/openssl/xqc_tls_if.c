#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_stack_cb.h"
#include "src/crypto/xqc_crypto_material.h"

static
int xqc_server_tls_handshake(xqc_connection_t * conn)
{
    int rv = 0;
    SSL * ssl = conn->xc_ssl;
    if(conn->tlsref.initial){//read 0 early data, because 0rtt data use quic standard
        char buf[2048];
        size_t nread;
        conn->tlsref.initial = 0;
        rv = SSL_read_early_data(ssl, buf, sizeof(buf), &nread); //nread always 0, read early data just for ssl status
        switch (rv) {
            case SSL_READ_EARLY_DATA_ERROR:
                {
                    int err = SSL_get_error(ssl, rv);
                    switch (err) {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                            {
                                return 0;
                            }
                        case SSL_ERROR_SSL:
                            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                            return XQC_ERR_CRYPTO;
                        default:
                            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                            return XQC_ERR_CRYPTO;
                    }
                    break;
                }
            case SSL_READ_EARLY_DATA_SUCCESS:
                // Reading 0-RTT data in TLS stream is a protocol violation.
                if (nread > 0) {
                    return XQC_ERR_PROTO;
                }
                break;
            case SSL_READ_EARLY_DATA_FINISH:
                break;
        }
    }

    rv = SSL_do_handshake(ssl);
    if( rv <= 0){
        int err = SSL_get_error(ssl, rv);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
        }
    }

    if(xqc_conn_handshake_completed(conn) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error: handshake completed callback return error|");
    }
    return 0;
}

static
int xqc_read_tls(SSL *ssl)
{
    ERR_clear_error();

    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));
    char buf[4096];
    size_t nread;

    for (;;) {
        int rv = SSL_read_ex(ssl, buf, sizeof(buf), &nread);
        if (rv == 1) {
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                xqc_log(conn->log, XQC_LOG_ERROR, "|Read  bytes from TLS crypto stream|");
                return XQC_ERR_PROTO;
            }else{
                continue;
            }
        }
        int err = SSL_get_error(ssl, 0);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS read error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return XQC_ERR_CRYPTO;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS read error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return XQC_ERR_CRYPTO;
        }
    }
    return 0;
}

static
int xqc_to_tls_handshake(xqc_connection_t *conn, const void * buf, size_t buf_len)
{
    if(conn->tlsref.hs_to_tls_buf) {
        xqc_free(conn->tlsref.hs_to_tls_buf);
        conn->tlsref.hs_to_tls_buf = NULL;
    }
    conn->tlsref.hs_to_tls_buf = xqc_create_hs_buffer(buf_len);
    if(conn->tlsref.hs_to_tls_buf == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc %d bytes failed|", buf_len);
        return -1;
    }

    xqc_hs_buffer_t  * p_data = conn->tlsref.hs_to_tls_buf;
    //p_data->type = XQC_FRAME_CRYPTO;
    p_data->data_len = buf_len;
    memcpy(p_data->data, buf, buf_len);

    return 0;//need finish
}


static
int xqc_client_tls_handshake(xqc_connection_t *conn)
{
    int rv;
    SSL *ssl = conn->xc_ssl;
    ERR_clear_error();

    if(conn->tlsref.initial && conn->tlsref.resumption && SSL_SESSION_get_max_early_data(SSL_get_session(ssl))){
        conn->tlsref.initial = 0;
        size_t nwrite;
        int rv = SSL_write_early_data(ssl, "", 0, &nwrite); //write 0 early data in order to generate early data key
        if(rv == 0){
            int err = SSL_get_error(ssl, rv);
            switch (err) {
                case SSL_ERROR_SSL:
                    xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                    return -1;
                default:
                    xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                    return -1;
            }
        }
    }

    rv = SSL_do_handshake(ssl);
    if( rv <= 0){
        int err = SSL_get_error(ssl, rv);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
        }
    }

    if(conn->tlsref.resumption ){

#if 0
        //for early data reject callbacks
        conn->tlsref.resumption = 0;
        if(SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED){
            xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was rejected by server|");
            printf("Early data was rejected by server\n");
            if(xqc_conn_early_data_rejected(conn) < 0){
                printf("Error do early data rejected action\n");
                xqc_log(conn->log, XQC_LOG_DEBUG, "|Error do early data rejected action|");
                return -1;
            }
        }else{
            xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was accepted by server|");
            printf("do early data accept\n");
            if(xqc_conn_early_data_accepted(conn) < 0){
                printf("error do early data accept action\n");
                xqc_log(conn->log, XQC_LOG_DEBUG, "|Error do early data accept action|");
            }
        }
#endif
    }
    xqc_conn_handshake_completed(conn);
    return 0;
}


int xqc_recv_crypto_data_cb(xqc_connection_t *conn, uint64_t offset,
        const uint8_t *data, size_t datalen,
        xqc_encrypt_level_t encrypt_level,
        void *user_data)
{

    if( xqc_to_tls_handshake(conn, data, datalen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|save crypto data to tls buffer error|");
        return -1;
    }
    if (!xqc_conn_get_handshake_completed(conn)) {

        if(conn->conn_type == XQC_CONN_TYPE_SERVER){
            if(xqc_server_tls_handshake(conn) < 0){
                xqc_log(conn->log, XQC_LOG_ERROR, "|error server handshake|");
                return -1;
            }
        }else{
            if(xqc_client_tls_handshake(conn) < 0){
                xqc_log(conn->log, XQC_LOG_ERROR, "|error client handshake|");
                return -1;
            }
        }
    }

    if(xqc_read_tls(conn->xc_ssl) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|error handshake|");
        return -1;
    }
    return 0;
}

//return 0 means forced 1RTT mode, return -1 means early data reject, return 1 means early data accept
int xqc_tls_is_early_data_accepted(xqc_connection_t * conn)
{
    if(conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
        if(conn->conn_type == XQC_CONN_TYPE_SERVER){
            SSL * ssl = conn->xc_ssl;
            if(SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED){
                xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was rejected by server|");
                return XQC_TLS_EARLY_DATA_REJECT ;
            }else{
                xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was accepted by server|");
                return  XQC_TLS_EARLY_DATA_ACCEPT ;
            }
        }else{
            if(conn->tlsref.resumption){

                SSL * ssl = conn->xc_ssl;
                if(SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED){
                    xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was rejected by server|");
                    return XQC_TLS_EARLY_DATA_REJECT ;
                }else{
                    xqc_log(conn->log, XQC_LOG_DEBUG, "|Early data was accepted by server|");
                    return  XQC_TLS_EARLY_DATA_ACCEPT ;
                }
            }else{
                return XQC_TLS_NO_EARLY_DATA ;
            }
        }
    }else{

        return XQC_TLS_EARLY_DATA_UNKNOWN;
    }

}


int xqc_client_initial_cb(xqc_connection_t *conn)
{
    return xqc_client_tls_handshake(conn);
}

static 
int xqc_recv_client_hello_derive_key( xqc_connection_t *conn, xqc_cid_t *dcid )
{
    int rv;

    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN]={0}, secret[INITIAL_SECRET_MAX_LEN]={0};
    rv = xqc_derive_initial_secret(
            initial_secret, sizeof(initial_secret), dcid,
            (const uint8_t *)(XQC_INITIAL_SALT),
            strlen(XQC_INITIAL_SALT));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive_initial_secret() failed|");
        return -1;
    }

    xqc_init_initial_crypto_ctx(conn);

    rv = xqc_derive_server_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive_server_initial_secret() failed|");
        return -1;
    }

    char key[16], iv[16], hp[16];

    ssize_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        return -1;
    }

    ssize_t ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed|");
        return -1;
    }

    ssize_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key failed|");
        return -1;
    }
    //need log

    if(xqc_conn_install_initial_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|install initial key error|");
        return -1;
    }

    rv = xqc_derive_client_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_client_initial_secret error|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key error|");
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv error|");
        return -1;
    }

    hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key error|");
        return -1;
    }

    if(xqc_conn_install_initial_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_initial_rx_keys error|");
        return -1;
    }

    return 0;
}

int xqc_recv_client_initial_cb(xqc_connection_t * conn,
        xqc_cid_t *dcid,
        void *user_data)
{
    return xqc_recv_client_hello_derive_key(conn, dcid);
}


ssize_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    ssize_t nwrite = xqc_crypto_encrypt(&ctx->aead,dest,destlen,plaintext,plaintextlen,key,keylen,nonce,noncelen,ad,adlen);
    if(nwrite < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_encrypt failed|ret code:%d |", nwrite);
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

ssize_t xqc_do_hs_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    ssize_t nwrite = xqc_crypto_decrypt(&ctx->aead,dest, destlen, ciphertext, ciphertextlen,
            key, keylen, nonce, noncelen, ad, adlen);

    if(nwrite < 0){
        return XQC_ERR_TLS_DECRYPT;
    }
    return nwrite;

}

ssize_t xqc_do_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    ssize_t nwrite = xqc_crypto_encrypt(&ctx->aead,dest, destlen, plaintext, plaintextlen , key, keylen,
                nonce, noncelen,  ad, adlen);
    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}


ssize_t xqc_do_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    ssize_t nwrite = xqc_crypto_decrypt(&ctx->aead,dest, destlen, ciphertext, ciphertextlen,
            key, keylen, nonce, noncelen, ad, adlen);
    if(nwrite < 0){
        return XQC_ERR_TLS_DECRYPT;
    }
    return nwrite;

}


ssize_t do_in_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    ssize_t nwrite = xqc_crypto_hp_mask(&ctx->hp, dest,destlen, key, keylen, sample,
                                         samplelen);

    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

ssize_t do_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    ssize_t nwrite = xqc_crypto_hp_mask(&ctx->hp,dest, destlen, key, keylen, sample,
                                         samplelen);

    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}
