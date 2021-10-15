
#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_0rtt.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_transport_params.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"


/**
 * select aplication layer proto, which will be triggered when processing ClientHello
 * only set for Server
 */
int 
xqc_alpn_select_proto_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, 
    const unsigned char *in, unsigned int inlen, void *arg)
{
    xqc_connection_t *conn = (xqc_connection_t *)SSL_get_app_data(ssl) ;
    xqc_engine_t *engine = (xqc_engine_t *)arg;
    uint8_t *alpn_list = engine->alpn_list;
    size_t alpn_list_len = engine->alpn_list_len;

    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_list, alpn_list_len, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|select proto error|");
        return SSL_TLSEXT_ERR_NOACK;
    }

    const unsigned char *alpn = (uint8_t *)(*out);
    size_t alpn_len = *outlen;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|select alpn|%*s|", alpn_len, alpn);

    xqc_int_t ret = xqc_conn_server_on_alpn(conn, alpn, alpn_len);
    if (XQC_OK != ret) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
}



int
xqc_do_update_key(xqc_connection_t *conn)
{

    char secret[64], key[64], iv[64];
    int keylen,ivlen, rv;

    xqc_tlsref_t *tlsref = &conn->tlsref;
    int secretlen = xqc_update_traffic_secret(secret, sizeof(secret), tlsref->tx_secret.base, tlsref->tx_secret.len, & tlsref->crypto_ctx);
    if(secretlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_update_traffic_secret  failed |ret code:%d |", secretlen);
        return -1;
    }

    xqc_vec_free(&tlsref->tx_secret);
    if(xqc_vec_assign(&tlsref->tx_secret, secret, secretlen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_vec_assign  failed|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(key, sizeof(key), secret, secretlen, &tlsref-> crypto_ctx);

    if(keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key failed| ret code:%d|", keylen);
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret, secretlen,  &tlsref->crypto_ctx);

    if(ivlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return -1;
    }

    rv = xqc_conn_update_tx_key(conn, key, keylen, iv, ivlen);
    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_update_tx_key failed| ret code:%d|", rv);
        return -1;
    }

    secretlen = xqc_update_traffic_secret(secret, sizeof(secret), tlsref->rx_secret.base, tlsref->rx_secret.len, & tlsref->crypto_ctx);

    if(secretlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_update_traffic_secret failed| ret code:%d|", secretlen);
        return -1;
    }

    xqc_vec_free(&tlsref->rx_secret);
    if(xqc_vec_assign(&tlsref->rx_secret, secret, secretlen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_vec_assign  failed|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(key, sizeof(key), secret, secretlen, &tlsref-> crypto_ctx);

    if(keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key failed| ret code:%d|", keylen);
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret, secretlen,  &tlsref->crypto_ctx);

    if(ivlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return -1;
    }

    rv = xqc_conn_update_rx_key(conn, key, keylen, iv, ivlen);
    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_update_tx_key failed| ret code:%d|", rv);
        return -1;
    }

    return 0;
}


int
xqc_update_key(xqc_connection_t *conn, void *user_data)
{
    if(xqc_do_update_key(conn) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_do_update_key failed|");
        return -1;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|key update|");
    return 0;
}


/*
 *  conn_commit_key_update rotates keys.  The current key moves to old
 *  key, and new key moves to the current key.
 */
int
xqc_conn_commit_key_update(xqc_connection_t *conn, uint64_t pkt_num)
{
    xqc_pktns_t *pktns = &conn->tlsref.pktns;

    xqc_tlsref_t *tlsref = & conn->tlsref;

    if(tlsref->new_tx_ckm.key.base == NULL || tlsref->new_tx_ckm.key.len == 0
       || tlsref->new_tx_ckm.iv.base == NULL || tlsref->new_tx_ckm.iv.len == 0)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|new key is not ready|");
        return -1;
    }

    xqc_vec_free(&tlsref->old_rx_ckm.key);
    xqc_vec_free(&tlsref->old_rx_ckm.iv);

    xqc_vec_move(&tlsref->old_rx_ckm.key, &pktns->rx_ckm.key);
    xqc_vec_move(&tlsref->old_rx_ckm.iv, &pktns->rx_ckm.iv);

    xqc_vec_move(&pktns->rx_ckm.key, &tlsref->new_rx_ckm.key);
    xqc_vec_move(&pktns->rx_ckm.iv, &tlsref->new_rx_ckm.iv);

    pktns->rx_ckm.flags = tlsref->new_rx_ckm.flags;
    pktns->rx_ckm.pkt_num = pkt_num;


    xqc_vec_free(&pktns->tx_ckm.key);
    xqc_vec_free(&pktns->tx_ckm.iv);
    xqc_vec_move(&pktns->tx_ckm.key, &tlsref->new_tx_ckm.key);
    xqc_vec_move(&pktns->tx_ckm.iv, & tlsref->new_tx_ckm.iv);
    pktns->tx_ckm.flags = tlsref->new_tx_ckm.flags;

    return 0;
}

