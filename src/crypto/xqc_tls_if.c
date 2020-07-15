#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_if.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_tls_stack_cb.h"


/*
 *@return XQC_FALSE means reject, XQC_TRUE means early accepted
 *
 */
int xqc_crypto_is_early_data_accepted(xqc_connection_t * conn) {
#ifndef OPENSSL_IS_BORINGSSL
    if(SSL_get_early_data_status(conn->xc_ssl) == SSL_EARLY_DATA_ACCEPTED) {
#else
    if(xqc_tls_is_early_data_accepted(conn) == XQC_TLS_EARLY_DATA_ACCEPT) {
#endif
        return XQC_TRUE;
    } else {
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

int xqc_free_pktns_list_buffer(xqc_pktns_t * p_pktns){

    xqc_list_head_t *head = &p_pktns->msg_cb_buffer;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head) {
        xqc_list_del(pos);
        xqc_free(pos);
    }

    return 0;
}

int xqc_tls_free_msg_cb_buffer(xqc_connection_t * conn){

    xqc_free_pktns_list_buffer(&conn->tlsref.initial_pktns);
    xqc_free_pktns_list_buffer(&conn->tlsref.hs_pktns);
    xqc_free_pktns_list_buffer(&conn->tlsref.pktns);

    return 0;
}

int xqc_handshake_completed_cb(xqc_connection_t *conn, void *user_data)
{
    //clear
    xqc_tls_free_msg_cb_buffer(conn);

    xqc_log(conn->log, XQC_LOG_DEBUG, "handshake completed callback\n");
    return 0;
}

int xqc_tls_recv_retry_cb(xqc_connection_t * conn,xqc_cid_t *dcid )
{
    if( (conn->conn_type == XQC_CONN_TYPE_SERVER) || ( conn->tlsref.flags & XQC_CONN_FLAG_RECV_RETRY)){
        xqc_log(conn->log, XQC_LOG_ERROR, "|server recv retry or client recv retry two or more times|");
        return -1;
    }
    conn->tlsref.flags  |= XQC_CONN_FLAG_RECV_RETRY;
    int ret = 0;
    //int ret = xqc_client_setup_initial_crypto_context(conn, dcid);

    xqc_pktns_t  * p_pktns = &conn->tlsref.initial_pktns;
    xqc_list_head_t *head = &p_pktns->msg_cb_buffer;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, head) {
        xqc_list_del(pos);
        xqc_list_add_tail(pos, & p_pktns->msg_cb_head);
    }

    return ret;
}


static
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

void xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen,
        uint64_t pkt_num) {
    size_t i;

    memcpy(dest, iv, ivlen);
    pkt_num = bswap64(pkt_num);

    for (i = 0; i < 8; ++i) {
        dest[ivlen - 8 + i] ^= ((uint8_t *)&pkt_num)[i];
    }
}

int xqc_conn_prepare_key_update(xqc_connection_t * conn)
{

    int rv;
    xqc_tlsref_t *tlsref = &conn->tlsref;
    if(xqc_judge_ckm_null(&tlsref->new_rx_ckm) == 1  || xqc_judge_ckm_null(&tlsref->new_tx_ckm) == 1){

        xqc_log(conn->log, XQC_LOG_DEBUG, "|error call xqc_conn_prepare_key_update because new_rx_ckm or new_tx_ckm is not null|");
        return -1;
    }

    if(tlsref->callbacks.update_key == NULL){

        xqc_log(conn->log, XQC_LOG_DEBUG, "|callback function update_key is null|");
        return -1;
    }

    rv = tlsref->callbacks.update_key(conn, NULL);

    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_DEBUG, "|update key error|");
        return rv;
    }
    return 0;
}

int xqc_start_key_update(xqc_connection_t * conn)
{
    if(xqc_do_update_key(conn) < 0){
        xqc_log(conn->log, XQC_LOG_DEBUG, "|start key error|");
        return -1;
    }

    if (conn->tlsref.flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        xqc_log(conn->log, XQC_LOG_DEBUG, "|flags error,cannot start key update|");
        return -1;
    }

    if(xqc_judge_ckm_null(& conn->tlsref.new_rx_ckm) != 1 ||
            xqc_judge_ckm_null(& conn->tlsref.new_tx_ckm) != 1){
        xqc_log(conn->log, XQC_LOG_DEBUG, "|new_rx_ckm is  null ,start key update error|");
        return -1;
    }

    if(xqc_conn_commit_key_update(conn, XQC_MAX_PKT_NUM) < 0){ //pkt num right? should be careful when integrated

        xqc_log(conn->log, XQC_LOG_DEBUG, "|update key commit error|");
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
int xqc_tls_check_rx_key_ready(xqc_connection_t * conn)
{
    xqc_pktns_t * pktns = &conn->tlsref.pktns;

    xqc_crypto_km_t * rx_ckm = & pktns->rx_ckm;
    xqc_vec_t * rx_hp = & pktns->rx_hp;

    if(rx_ckm->key.base == NULL || rx_ckm->key.len == 0){
        return 0;
    }

    if(rx_ckm->iv.base == NULL || rx_ckm->iv.len == 0){
        return 0;
    }

    if(rx_hp->base == NULL || rx_hp->len == 0){
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

//0 means not ready, 1 means ready
int xqc_tls_check_hs_rx_key_ready(xqc_connection_t * conn)
{
    xqc_pktns_t * pktns = &conn->tlsref.hs_pktns;

    xqc_crypto_km_t * rx_ckm = & pktns->rx_ckm;
    xqc_vec_t * rx_hp = & pktns->rx_hp;

    if(rx_ckm->key.base == NULL || rx_ckm->key.len == 0){
        return 0;
    }

    if(rx_ckm->iv.base == NULL || rx_ckm->iv.len == 0){
        return 0;
    }

    if(rx_hp->base == NULL || rx_hp->len == 0){
        return 0;
    }

    return 1;
}

//0 means not ready, 1 means ready
int xqc_tls_check_0rtt_key_ready(xqc_connection_t * conn)
{
    xqc_crypto_km_t *p_ckm = &(conn->tlsref.early_ckm);
    xqc_vec_t * p_hp = &(conn->tlsref.early_hp);

    if(p_ckm->key.base == NULL || p_ckm->key.len == 0){
        return 0;
    }

    if(p_ckm->iv.base == NULL || p_ckm->iv.len == 0){
        return 0;
    }

    if(p_hp->base == NULL || p_hp->len == 0){
        return 0;
    }

    return 1;

}

int xqc_tls_free_ckm(xqc_crypto_km_t * p_ckm){
    xqc_vec_free(&p_ckm->key);
    xqc_vec_free(&p_ckm->iv);
    return 0;
}

int xqc_tls_free_pktns(xqc_pktns_t * p_pktns){

    if(p_pktns == NULL)return 0;
    xqc_crypto_km_t * p_ckm = & p_pktns->rx_ckm;
    xqc_tls_free_ckm(p_ckm);

    p_ckm = &p_pktns->tx_ckm;
    xqc_tls_free_ckm(p_ckm);

    xqc_vec_free(&p_pktns->rx_hp);
    xqc_vec_free(&p_pktns->tx_hp);

    xqc_list_head_t *head = &p_pktns->msg_cb_head;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head) {
        xqc_list_del(pos);
        xqc_free(pos);
    }

    head = &p_pktns->msg_cb_buffer;
    xqc_list_for_each_safe(pos, next, head) {
        xqc_list_del(pos);
        xqc_free(pos);
    }
    return 0;

}

int xqc_tls_free_engine_config(xqc_engine_ssl_config_t *ssl_config)
{

    if(ssl_config->private_key_file)xqc_free(ssl_config->private_key_file);
    if(ssl_config->cert_file)xqc_free(ssl_config->cert_file);
    if(ssl_config->ciphers)xqc_free(ssl_config->ciphers);
    if(ssl_config->groups)xqc_free(ssl_config->groups);
    if(ssl_config->session_ticket_key_data)xqc_free(ssl_config->session_ticket_key_data);
    if(ssl_config->alpn_list)xqc_free(ssl_config->alpn_list);
    memset(ssl_config, 0, sizeof(xqc_engine_ssl_config_t));
    return 0;
}


int xqc_tls_free_ssl_config(xqc_conn_ssl_config_t * ssl_config){

    if(ssl_config->session_ticket_data){
        xqc_free(ssl_config->session_ticket_data);
        ssl_config->session_ticket_data = NULL;
    }
    if(ssl_config->transport_parameter_data){
        xqc_free(ssl_config->transport_parameter_data);
        ssl_config->transport_parameter_data = NULL;
    }
    if(ssl_config->alpn){
        xqc_free(ssl_config->alpn);
        ssl_config->alpn = NULL;
    }
    return 0;
}

int xqc_tls_free_tlsref(xqc_connection_t * conn)
{
    xqc_tlsref_t * tlsref = &conn->tlsref;

    //
    xqc_tls_free_pktns(&tlsref->initial_pktns);
    xqc_tls_free_pktns(&tlsref->hs_pktns);
    xqc_tls_free_pktns(&tlsref->pktns);

    xqc_tls_free_ckm(&tlsref->early_ckm);
    xqc_vec_free(&tlsref->early_hp);

    xqc_tls_free_ckm(&tlsref->new_tx_ckm);
    xqc_tls_free_ckm(&tlsref->new_rx_ckm);
    xqc_tls_free_ckm(&tlsref->old_rx_ckm);

    xqc_vec_free(&tlsref->tx_secret);
    xqc_vec_free(&tlsref->rx_secret);

    if(tlsref->hs_to_tls_buf){
        xqc_free(tlsref->hs_to_tls_buf);
    }

    xqc_tls_free_ssl_config(&tlsref->conn_ssl_config);

    return 0;

}


ssize_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    xqc_tls_context_t *ctx = & conn->tlsref.hs_crypto_ctx;
    ssize_t nwrite = xqc_aead_encrypt(&ctx->aead,dest,destlen,plaintext,plaintextlen,key,keylen,nonce,noncelen,ad,adlen);
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
    ssize_t nwrite = xqc_aead_decrypt(&ctx->aead,dest, destlen, ciphertext, ciphertextlen,
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
    ssize_t nwrite = xqc_aead_encrypt(&ctx->aead,dest, destlen, plaintext, plaintextlen , key, keylen,
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
    ssize_t nwrite = xqc_aead_decrypt(&ctx->aead,dest, destlen, ciphertext, ciphertextlen,
            key, keylen, nonce, noncelen, ad, adlen);
    if(nwrite < 0){
        return XQC_ERR_TLS_DECRYPT;
    }
    return nwrite;

}

ssize_t
xqc_in_hp_mask_cb(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
   const uint8_t *key, size_t keylen, const uint8_t *sample,
   size_t samplelen, void *user_data)
{
    xqc_tls_context_t *ctx = &conn->tlsref.hs_crypto_ctx;
    ssize_t nwrite = xqc_crypto_encrypt(&ctx->hp, dest, destlen, XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK)-1, key, keylen, sample, samplelen);
    if (nwrite < 0) {
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

ssize_t
xqc_hp_mask_cb(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
    const uint8_t *key, size_t keylen, const uint8_t *sample,
    size_t samplelen, void *user_data)
{
    xqc_tls_context_t *ctx = &conn->tlsref.crypto_ctx;
    ssize_t nwrite = xqc_crypto_encrypt(&ctx->hp, dest, destlen, XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK)-1, key, keylen, sample, samplelen);
    if (nwrite < 0) {
        return XQC_ERR_CALLBACK_FAILURE;
    }
    return nwrite;
}

