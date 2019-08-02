#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <assert.h>
#include "transport/xqc_conn.h"
#include "xqc_tls_if.h"
#include "xqc_tls_init.h"

#include "xqc_tls_cb.h"


static inline int xqc_conn_get_handshake_completed(xqc_connection_t *conn)
{
    return (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX) &&
        (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED);
}

void xqc_conn_handshake_completed(xqc_connection_t *conn)
{
    conn->tlsref.flags |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX;
}



/*
 *call ssl to generate handshake data
 *@return 0 means success
 */
int xqc_tls_handshake(xqc_connection_t *conn)
{
    return 0;
}

int xqc_server_tls_handshake(xqc_connection_t * conn)
{
    int rv = 0;
    SSL * ssl = conn->xc_ssl;
    if(conn->tlsref.initial){
        char buf[2048];
        size_t nread;
        conn->tlsref.initial = 0;
        rv = SSL_read_early_data(ssl, buf, sizeof(buf), &nread);
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
                            xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                            printf("TLS handshake error: %s \n", ERR_error_string(ERR_get_error(), NULL));
                            return XQC_ERR_CRYPTO;
                        default:
                            xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                            printf("TLS handshake error: %s \n", ERR_error_string(ERR_get_error(), NULL));
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
                xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                printf("TLS handshake error: %s \n", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                printf("TLS handshake error\n");
                return -1;
        }
    }

    xqc_conn_handshake_completed(conn);
    return 0;
}

int xqc_conn_early_data_rejected(xqc_connection_t * conn)
{
    conn->tlsref.flags |= XQC_CONN_FLAG_EARLY_DATA_REJECTED;
    if(conn->tlsref.early_data_cb != NULL){
        return conn->tlsref.early_data_cb(conn, 0);
    }

    return 0;
}

int xqc_conn_early_data_accepted(xqc_connection_t * conn)
{
    conn->tlsref.flags &= ~(XQC_CONN_FLAG_EARLY_DATA_REJECTED);
    if(conn->tlsref.early_data_cb != NULL){
        return conn->tlsref.early_data_cb(conn, 1);
    }

    return 0;
}



/*
 *@return XQC_FALSE means not reject, XQC_TRUE means early reject
 *
 */
int xqc_is_early_data_reject(xqc_connection_t * conn)
{
    if(conn->tlsref.resumption  == 0){
        return XQC_TRUE;
    }

    if(conn->tlsref.flags & XQC_CONN_FLAG_EARLY_DATA_REJECTED != 0){
        return XQC_TRUE;
    }else{
        return XQC_FALSE;
    }
}

/*
 *@return  XQC_FALSE means not ready, XQC_TRUE means ready
 */
int xqc_is_ready_to_send_early_data(xqc_connection_t * conn)
{

    if(conn->tlsref.resumption == 0){
        return XQC_FALSE;
    }
    if(conn->tlsref.early_ckm.key.len  <= 0 || conn->tlsref.early_ckm.key.base == NULL ){
        return XQC_FALSE;
    }
    if(conn->tlsref.early_ckm.iv.len <= 0 || conn->tlsref.early_ckm.iv.base == NULL) {
        return XQC_FALSE;
    }
    if(conn->tlsref.early_hp.len <= 0 || conn->tlsref.early_hp.base == NULL){
        return XQC_FALSE;
    }
    return XQC_TRUE;
}



int xqc_client_tls_handshake(xqc_connection_t *conn, int initial)
{
    int rv;
    SSL *ssl = conn->xc_ssl;
    ERR_clear_error();

    if(initial && conn->tlsref.resumption && SSL_SESSION_get_max_early_data(SSL_get_session(ssl))){

        size_t nwrite;
        int rv = SSL_write_early_data(ssl, "", 0, &nwrite);
        if(rv == 0){
            int err = SSL_get_error(ssl, rv);
            switch (err) {
                case SSL_ERROR_SSL:
                    xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                    printf("TLS handshake error: %s\n",ERR_error_string(ERR_get_error(), NULL));
                    return -1;
                default:
                    xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                    printf("TLS handshake error: %s\n",ERR_error_string(ERR_get_error(), NULL));
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
                xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                printf("TLS handshake error: %s \n", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                printf("TLS handshake error\n");
                return -1;
        }
    }

    if(conn->tlsref.resumption ){

#if 0
        //conn->tlsref.resumption = 0;

        if(SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED){
            xqc_log(conn->log, XQC_LOG_DEBUG, "Early data was rejected by server|");
            printf("Early data was rejected by server\n");
            if(xqc_conn_early_data_rejected(conn) < 0){
                printf("Error do early data rejected action\n");
                xqc_log(conn->log, XQC_LOG_DEBUG, "Error do early data rejected action|");
                return -1;
            }
        }else{

            xqc_log(conn->log, XQC_LOG_DEBUG, "Early data was accepted by server|");
            printf("do early data accept\n");
            if(xqc_conn_early_data_accepted(conn) < 0){
                printf("error do early data accept action\n");
                xqc_log(conn->log, XQC_LOG_DEBUG, "Error do early data accept action|");
            }
        }
#endif
    }
    xqc_conn_handshake_completed(conn);
    return 0;
}


//return 0 means forced 1RTT mode, return -1 means early data reject, return 1 means early data accept
int xqc_tls_is_early_data_accepted(xqc_connection_t * conn)
{

    if(conn->tlsref.resumption){

        SSL * ssl = conn->xc_ssl;
        if(SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED){
            xqc_log(conn->log, XQC_LOG_DEBUG, "Early data was rejected by server|");
            return XQC_TLS_EARLY_DATA_REJECT ;
        }else{
            xqc_log(conn->log, XQC_LOG_DEBUG, "Early data was accepted by server|");
            return  XQC_TLS_EARLY_DATA_ACCEPT ;
        }
    }else{
        return XQC_TLS_NO_EARLY_DATA ;
    }

}


int xqc_client_initial_cb(xqc_connection_t *conn)
{
    return xqc_client_tls_handshake(conn , 1);
}

int xqc_recv_client_hello_derive_key( xqc_connection_t *conn, xqc_cid_t *dcid )
{
    int rv;

    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN]={0}, secret[INITIAL_SECRET_MAX_LEN]={0};
    rv = xqc_derive_initial_secret(
            initial_secret, sizeof(initial_secret), dcid,
            (const uint8_t *)(XQC_INITIAL_SALT),
            strlen(XQC_INITIAL_SALT));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "derive_initial_secret() failed|");
        printf("derive_initial_secret() failed\n");
        return -1;
    }

    xqc_prf_sha256(& conn->tlsref.hs_crypto_ctx);
    xqc_aead_aes_128_gcm(& conn->tlsref.hs_crypto_ctx);

    rv = xqc_derive_server_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "derive_server_initial_secret() failed|");
        printf("derive_server_initial_secret() failed\n");
        return -1;
    }

    char key[16], iv[16], hp[16];

    size_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        return -1;
    }

    size_t ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_packet_protection_iv failed|");
        return -1;
    }

    size_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_header_protection_key failed|");
        return -1;
    }
    //need log

    if(xqc_conn_install_initial_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        printf("install initial key error\n");
        xqc_log(conn->log, XQC_LOG_ERROR, "install initial key error|");
        return -1;
    }

    rv = xqc_derive_client_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_client_initial_secret error|");
        printf("derive_server_initial_secret() failed\n");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_packet_protection_key error|");
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_packet_protection_iv error|");
        return -1;
    }

    hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_derive_header_protection_key error|");
        return -1;
    }

    if(xqc_conn_install_initial_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        printf("install initial key error\n");
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_conn_install_initial_rx_keys error|");
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


int xqc_read_tls(SSL *ssl)
{
    ERR_clear_error();

    char buf[4096];
    size_t nread;

    for (;;) {
        int rv = SSL_read_ex(ssl, buf, sizeof(buf), &nread);
        if (rv == 1) {
            printf("Read  bytes from TLS crypto stream\n");
            //xqc_log(conn->log, XQC_LOG_ERROR, "Read  bytes from TLS crypto stream|");
            return XQC_ERR_PROTO;
        }
        int err = SSL_get_error(ssl, 0);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
                printf("TLS read error: %s\n", ERR_error_string(ERR_get_error(), NULL));
                //xqc_log(conn->log, XQC_LOG_ERROR, "TLS read error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return XQC_ERR_CRYPTO;
            default:
                //xqc_log(conn->log, XQC_LOG_ERROR, "TLS read error:%s|", ERR_error_string(ERR_get_error(), NULL));
                printf("TLS read error: %d\n", err);
                return XQC_ERR_CRYPTO;
        }
    }
    return 0;
}


int xqc_to_tls_handshake(xqc_connection_t *conn, const void * buf, size_t buf_len)
{
    xqc_hs_buffer_t  * p_data = &conn-> tlsref.hs_to_tls_buf;
    //p_data->type = XQC_FRAME_CRYPTO;
    p_data->data_len = buf_len;
    memcpy(p_data->data, buf, buf_len);

    return 0;//need finish
}


int xqc_recv_crypto_data_cb(xqc_connection_t *conn, uint64_t offset,
        const uint8_t *data, size_t datalen,
        void *user_data)
{

    xqc_to_tls_handshake(conn, data, datalen);
    if (!xqc_conn_get_handshake_completed(conn)) {

        if(conn->conn_type == XQC_CONN_TYPE_SERVER){
            if(xqc_server_tls_handshake(conn) < 0){
                return -1;
            }
        }else{
            if(xqc_client_tls_handshake(conn, 0) < 0){
                return -1;
            }
        }
    }

    if(xqc_read_tls(conn->xc_ssl) < 0){
        return -1;
    }
    return 0;
}

int xqc_handshake_completed_cb(xqc_connection_t *conn, void *user_data)
{
    return 0;
}

size_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    size_t nwrite;
#if 0
    if(conn -> local_settings.no_crypto == 1){
        nwrite = xqc_no_encrypt(dest, destlen, plaintext, plaintextlen, ctx, key, keylen,
                nonce, noncelen,  ad, adlen);
    }else{
        nwrite = xqc_encrypt(dest, destlen, plaintext, plaintextlen, ctx, key, keylen,
                nonce, noncelen,  ad, adlen);
    }
#endif
    nwrite = xqc_encrypt(dest, destlen, plaintext, plaintextlen, ctx, key, keylen,
            nonce, noncelen,  ad, adlen);

    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

size_t xqc_do_hs_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    size_t nwrite;
#if 0
    if(conn -> local_settings.no_crypto == 1){
       nwrite = xqc_no_decrypt(dest, destlen, ciphertext, ciphertextlen, ctx,
               key, keylen, nonce, noncelen, ad, adlen);
    }else{
        nwrite = xqc_decrypt(dest, destlen, ciphertext, ciphertextlen, ctx,
                 key, keylen, nonce, noncelen, ad, adlen);
    }
#endif
    nwrite = xqc_decrypt(dest, destlen, ciphertext, ciphertextlen, ctx,
            key, keylen, nonce, noncelen, ad, adlen);

    if(nwrite < 0){
        return XQC_ERR_TLS_DECRYPT;
    }
    return nwrite;

}

size_t xqc_do_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    size_t nwrite;
    if(conn -> local_settings.no_crypto == 1){
        nwrite = xqc_no_encrypt(dest, destlen, plaintext, plaintextlen, ctx, key, keylen,
                nonce, noncelen,  ad, adlen);
    }else{
        nwrite = xqc_encrypt(dest, destlen, plaintext, plaintextlen, ctx, key, keylen,
                nonce, noncelen,  ad, adlen);
    }
    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}


size_t xqc_do_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    size_t nwrite;
    if(conn -> local_settings.no_crypto == 1){
       nwrite = xqc_no_decrypt(dest, destlen, ciphertext, ciphertextlen, ctx,
               key, keylen, nonce, noncelen, ad, adlen);
    }else{
        nwrite = xqc_decrypt(dest, destlen, ciphertext, ciphertextlen, ctx,
                 key, keylen, nonce, noncelen, ad, adlen);
    }
    if(nwrite < 0){
        return XQC_ERR_TLS_DECRYPT;
    }
    return nwrite;

}


size_t do_in_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    size_t nwrite;
#if 0
    if(conn -> local_settings.no_crypto == 1){
        nwrite = xqc_no_hp_mask(dest, destlen, ctx, key, keylen, sample,
                         samplelen);
    }else{
    }
#endif
    nwrite = xqc_hp_mask(dest, destlen, ctx, key, keylen, sample,
                                         samplelen);

    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

size_t do_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{

    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx;
    size_t nwrite;
    if(conn -> local_settings.no_crypto == 1){
        nwrite = xqc_no_hp_mask(dest, destlen, ctx, key, keylen, sample,
                         samplelen);
    }else{
        nwrite = xqc_hp_mask(dest, destlen, ctx, key, keylen, sample,
                                         samplelen);
    }

    if(nwrite < 0){
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}


static int xqc_conn_handshake_completed_handled(xqc_connection_t *conn)
{
  int rv;

  conn->tlsref.flags |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED;

  if(conn->tlsref.callbacks.handshake_completed){

    rv = conn->tlsref.callbacks.handshake_completed(conn, NULL);
  }
  if (rv != 0) {
    return rv;
  }


  return 0;
}


int xqc_judge_ckm_null(xqc_crypto_km_t * ckm)//if null return 0, both key and iv not null return 1, else return -1;
{
    if((ckm->key.base == NULL && ckm->key.len == 0) && (ckm->iv.base == NULL && ckm->iv.len == 0)){
        return  0;
    }

    if((ckm->key.base != NULL && ckm->key.len != 0) && (ckm->iv.base != NULL && ckm->iv.len != 0)){
        return 1;
    }

    return -1;
}

int xqc_conn_prepare_key_update(xqc_connection_t * conn)
{

    int rv;
    xqc_tlsref_t *tlsref = &conn->tlsref;
    if(xqc_judge_ckm_null(&tlsref->new_rx_ckm) == 1  || xqc_judge_ckm_null(&tlsref->new_tx_ckm) == 1){

        xqc_log(conn->log, XQC_LOG_DEBUG, "error call xqc_conn_prepare_key_update because new_rx_ckm or new_tx_ckm is not null|");
        printf("error call xqc_conn_prepare_key_update because new_rx_ckm or new_tx_ckm is not null\n");
        return -1;
    }

    if(tlsref->callbacks.update_key == NULL){

        xqc_log(conn->log, XQC_LOG_DEBUG, "callback function update_key is null|");
        printf("callback function update_key is null \n");
        return -1;
    }

    rv = tlsref->callbacks.update_key(conn, NULL);

    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_DEBUG, "update key error|");
        printf("update key error \n");
        return rv;
    }
    return 0;
}

int xqc_start_key_update(xqc_connection_t * conn)
{
    if(xqc_do_update_key(conn) < 0){
        xqc_log(conn->log, XQC_LOG_DEBUG, "start key error");
        printf("start key error\n");
        return -1;
    }

    if (conn->tlsref.flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        xqc_log(conn->log, XQC_LOG_DEBUG, "flags error,cannot start key update|");
        printf("flags error,cannot start key update\n");
        return -1;
    }

    if(xqc_judge_ckm_null(& conn->tlsref.new_rx_ckm) != 1 ||
            xqc_judge_ckm_null(& conn->tlsref.new_tx_ckm) != 1){
        printf("new_rx_ckm is  null ,start key update error\n");
        xqc_log(conn->log, XQC_LOG_DEBUG, "new_rx_ckm is  null ,start key update error|");
        return -1;
    }

    if(xqc_conn_commit_key_update(conn, XQC_MAX_PKT_NUM) < 0){ //pkt num right? should be careful when integrated

        printf("update key commit error\n");
        xqc_log(conn->log, XQC_LOG_DEBUG, "update key commit error|");
        return -1;
    }
    conn->tlsref.flags |= XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE;
    return 0;
}

//0 means not ready, 1 means ready
int xqc_tls_check_tx_key_ready(xqc_connection_t * conn)
{
    xqc_pktns_t * pktns = &conn->tlsref.pktns;

    xqc_crypto_km_t * tx_ckm = & pktns->tx_ckm;
    xqc_vec_t * tx_hp = & pktns->tx_hp;

    if(tx_ckm->key.base == NULL || tx_ckm->key.len == 0){
        return 0;
    }

    if(tx_ckm->iv.base == NULL || tx_ckm->iv.len == 0){
        return 0;
    }

    if(tx_hp->base == NULL || tx_hp->len == 0){
        return 0;
    }

    return 1;

}


//0 means not ready, 1 means ready
int xqc_tls_check_hs_tx_key_ready(xqc_connection_t * conn)
{
    xqc_pktns_t * pktns = &conn->tlsref.hs_pktns;

    xqc_crypto_km_t * tx_ckm = & pktns->tx_ckm;
    xqc_vec_t * tx_hp = & pktns->tx_hp;

    if(tx_ckm->key.base == NULL || tx_ckm->key.len == 0){
        return 0;
    }

    if(tx_ckm->iv.base == NULL || tx_ckm->iv.len == 0){
        return 0;
    }

    if(tx_hp->base == NULL || tx_hp->len == 0){
        return 0;
    }

    return 1;
}

