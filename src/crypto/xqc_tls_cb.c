#include <stdio.h>
#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_conn.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_0rtt.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_transport_params.h"

/*
 * key callback
 *@param
 *@return 0 mearns error, no zero means no error
 */

int xqc_do_tls_key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen, void *arg)
{
    int rv;
    xqc_connection_t *conn = (xqc_connection_t *)arg;

    switch (name) {
        case SSL_KEY_CLIENT_EARLY_TRAFFIC:
        case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
        case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
            break;
        case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
            //update traffic key ,should completed

            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(conn->tlsref.rx_secret.base != NULL){ // should xqc_vec_free ? if rx_secret already has value, it means connection status error
                    xqc_log(conn->log, XQC_LOG_WARN, "|error rx_secret , may case memory leak |");
                }
                if(xqc_vec_assign(&conn->tlsref.rx_secret, secret, secretlen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|error assign rx_secret |");
                    return -1;
                }

            }else{
                if(conn->tlsref.tx_secret.base != NULL){
                    xqc_log(conn->log, XQC_LOG_WARN, "|error tx_secret , may case memory leak |");
                }
                if(xqc_vec_assign(&conn->tlsref.tx_secret, secret, secretlen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|error assign tx_secret |");
                    return -1;
                }
            }
            break;
        case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
            //for
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(conn->tlsref.tx_secret.base != NULL){
                    xqc_log(conn->log, XQC_LOG_WARN, "|error tx_secret , may case memory leak |");
                }
                if(xqc_vec_assign(&conn->tlsref.tx_secret, secret, secretlen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|error assign tx_secret |");
                    return -1;
                }

            }else{
                if(conn->tlsref.rx_secret.base != NULL){
                    xqc_log(conn->log, XQC_LOG_WARN, "|error rx_secret , may case memory leak |");
                }
                if(xqc_vec_assign(&conn->tlsref.rx_secret, secret, secretlen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|error assign rx_secret |");
                    return -1;
                }
            }

            break;
        default:
            return 0;
    }


    // call it every time 
    xqc_init_crypto_ctx(conn,SSL_get_current_cipher(ssl));


    uint8_t key[64] = {0}, iv[64] = {0}, hp[64] = {0}; //need check 64 bytes enough
    ssize_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, secretlen, & conn->tlsref.crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key failed|ret code:%d|", keylen);
        return -1;
    }

    ssize_t ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret,
            secretlen, & conn->tlsref.crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return -1;
    }

    ssize_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, secretlen, & conn->tlsref.crypto_ctx);

    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key failed| ret code:%d|", hplen);
        return -1;
    }

    switch (name) {
        case SSL_KEY_CLIENT_EARLY_TRAFFIC:
            if(xqc_conn_install_early_keys(conn, key, keylen, iv, ivlen,
                        hp, hplen) < 0){
                xqc_log(conn->log, XQC_LOG_ERROR, "|install early keys error|");
                return -1;
            }
            break;
        case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(xqc_conn_install_handshake_rx_keys(conn, key, keylen, iv,
                            ivlen, hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_handshake_rx_keys  failed|");
                    return -1;
                }
            }else{
                if(xqc_conn_install_handshake_tx_keys(conn, key, keylen, iv,
                            ivlen, hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_handshake_tx_keys  failed|");
                    return -1;
                }

            }
            break;
        case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(xqc_conn_install_rx_keys(conn, key, keylen, iv, ivlen,
                            hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_rx_keys  failed|");
                    return -1;
                }
            }else{
                if(xqc_conn_install_tx_keys(conn, key, keylen, iv, ivlen,
                            hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_tx_keys  failed|");
                    return -1;

                }
            }
            break;
        case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(xqc_conn_install_handshake_tx_keys(conn, key, keylen, iv,
                            ivlen, hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_handshake_tx_keys  failed|");
                    return -1;
                }
            }else{
                if(xqc_conn_install_handshake_rx_keys(conn, key, keylen, iv,
                            ivlen, hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_handshake_rx_keys  failed|");
                    return -1;
                }

            }
            break;
        case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
            if(conn->conn_type == XQC_CONN_TYPE_SERVER){
                if(xqc_conn_install_tx_keys(conn, key, keylen, iv, ivlen,
                            hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_tx_keys  failed|");
                    return -1;
                }
            }else{
                if(xqc_conn_install_rx_keys(conn, key, keylen, iv, ivlen,
                            hp, hplen) < 0){
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_rx_keys  failed|");
                    return -1;
                }
            }
            break;
    }

    return 0;
}


int xqc_tls_key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen, void *arg)
{
    int ret = xqc_do_tls_key_cb(ssl, name, secret, secretlen, arg);
    if(ret == 0){
        return 1;//兼容openssl return value
    }else{
        return 0;
    }
}


int xqc_cache_client_hello(xqc_connection_t *conn, const void * buf, size_t buf_len)
{
    return 0;
}

int xqc_cache_server_handshake(xqc_connection_t *conn, const void * buf, size_t buf_len)
{

    return 0;
}


int xqc_msg_cb_handshake(xqc_connection_t *conn, const void * buf, size_t buf_len)
{
    xqc_list_head_t  * phead = NULL;
    xqc_pktns_t * pktns = NULL;

    if(conn->tlsref.pktns.tx_ckm.key.base != NULL && conn->tlsref.pktns.tx_ckm.key.len > 0){
        pktns = & conn->tlsref.pktns;
        phead = & pktns->msg_cb_head;
    }else if(conn->tlsref.hs_pktns.tx_ckm.key.base != NULL && conn->tlsref.hs_pktns.tx_ckm.key.len > 0){
        pktns = &conn->tlsref.hs_pktns;
        phead = & pktns->msg_cb_head;
    }else{
        pktns = & conn->tlsref.initial_pktns;
        if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0){
            phead = & pktns->msg_cb_head;
        }else{
            xqc_log(conn->log, XQC_LOG_ERROR, "|error msg_cb_handshake|%p:%d",pktns->tx_ckm.key.base,pktns->tx_ckm.key.len);
            return -1;
        }
    }
    
    xqc_hs_buffer_t  * p_data = xqc_create_hs_buffer(buf_len);
    if(p_data == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_hs_buffer failed|");
        return -1;
    }
    memcpy(p_data->data, buf, buf_len);

    xqc_list_add_tail(& p_data->list_head, phead);
    return 0;
}

void xqc_msg_cb(int write_p, int version, int content_type, const void *buf,
        size_t len, SSL *ssl, void *arg)
{
    int rv;
    xqc_connection_t *conn = (xqc_connection_t *)arg;

    if (!write_p) {
        return;
    }

    unsigned char * msg = (unsigned char *)buf;
    switch (content_type) {
        case SSL3_RT_HANDSHAKE:
            break;
        case SSL3_RT_ALERT:
            //assert(len == 2);
            if (msg[0] != 2 /* FATAL */) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|msg cb content error|");
                return;
            }
            //set_tls_alert(msg[1]); //need finish
            xqc_log(conn->log, XQC_LOG_ERROR, "|msg cb content_type error,(SSL3_RT_ALERT) may use error openssl version|content_type:%d|", content_type);
            return;
        default:
            xqc_log(conn->log, XQC_LOG_ERROR, "|msg cb content_type error, may use error openssl version |content_type:%d |", content_type);
            return;
    }

    rv = xqc_msg_cb_handshake(conn, buf, len);

    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| do  handshare failed|");
    }
    //assert(0 == rv);
}

/*select aplication layer proto, now only just support XQC_ALPN_V1
 *
 */
int xqc_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
        unsigned char *outlen, const unsigned char *in,
        unsigned int inlen, void *arg)
{
    xqc_connection_t * conn = (xqc_connection_t *) SSL_get_app_data(ssl) ;
    xqc_engine_ssl_config_t *xs_config = (xqc_engine_ssl_config_t *)arg;
    uint8_t *alpn_list = xs_config->alpn_list;
    size_t alpn_list_len = xs_config->alpn_list_len;

    if(SSL_select_next_proto((unsigned char **)out, outlen, alpn_list, alpn_list_len, in, inlen ) != OPENSSL_NPN_NEGOTIATED){
        return SSL_TLSEXT_ERR_NOACK;
    }

    uint8_t * alpn = (uint8_t *)(*out);
    uint8_t alpn_len = *outlen;

    if(alpn_len == strlen(XQC_ALPN_TRANSPORT) && memcmp(alpn, XQC_ALPN_TRANSPORT, alpn_len) == 0){
        conn->tlsref.alpn_num = XQC_ALPN_TRANSPORT_NUM;
    }else{
        conn->tlsref.alpn_num = XQC_ALPN_HTTP3_NUM;
    }

    xqc_conn_server_on_alpn(conn);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|select apln number:%d|", conn->tlsref.alpn_num);

#if 0
    int version = conn->version ;
    // Just select alpn for now.
    switch (version) {
        case XQC_QUIC_VERSION:
            alpn = XQC_ALPN_V1;
            alpnlen = strlen(XQC_ALPN_V1);
            break;
        default:
            return SSL_TLSEXT_ERR_NOACK;
    }
    *out = (const uint8_t *)(alpn + 1);
    *outlen = alpn[0];
#endif


    return SSL_TLSEXT_ERR_OK;
}


/*
 * conn_client_validate_transport_params validates |params| as client.
 * |params| must be sent with Encrypted Extensions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * XQC_ERR_VERSION_NEGOTIATION
 *     The negotiated version is invalid.
 */


int xqc_server_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg)
{
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));
    if (context != SSL_EXT_CLIENT_HELLO) {
        *al = SSL_AD_ILLEGAL_PARAMETER;
        xqc_log(conn->log, XQC_LOG_ERROR, "| ssl ad illegal parameter | ");
        return -1;
    }

    int rv = xqc_on_server_recv_peer_transport_params(conn,in,inlen);
    if(XQC_UNLIKELY(rv != 0)) {
        *al = SSL_AD_ILLEGAL_PARAMETER ;
        return -1;
    }

    return 1;
}

#define XQC_TRANSPORT_PARAM_BUF_LEN (512)
int xqc_server_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg)
{
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));
    int rv = xqc_serialize_server_transport_params(conn,XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,out,outlen);
    if(XQC_UNLIKELY(rv != 0)){
        *al = SSL_AD_INTERNAL_ERROR ;
        return 01;
    }
    return 1;
}

//need finish , need test for malloc xqc_free
void xqc_transport_params_free_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *out,
        void *add_arg)
{
    xqc_transport_parames_serialization_free((void*)(out));
}

int xqc_client_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int content, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg)
{
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));
    int rv = xqc_serialize_client_transport_params(conn,XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,out,outlen);
    if(rv != 0) {
        xqc_log(conn->log,XQC_LOG_ERROR,"xqc_client_transport_params_add_cb failed");
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }
    return 1;
}

int xqc_client_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg)
{
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));
    int rv = xqc_on_client_recv_peer_transport_params(conn,in,inlen);
    if(rv != 0 ) {
        xqc_log(conn->log,XQC_LOG_ERROR,"xqc_client_transport_params_parse_cb failed");
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }
    return 1;
}


int xqc_do_update_key(xqc_connection_t *conn)
{

    char secret[64], key[64], iv[64];
    //conn->tlsref.nkey_update++;g
    int keylen,ivlen, rv;

    xqc_tlsref_t *tlsref = &conn->tlsref;
    int secretlen = xqc_update_traffic_secret(secret, sizeof(secret), tlsref->tx_secret.base, tlsref->tx_secret.len, & tlsref->crypto_ctx);
    if(secretlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_update_traffic_secret  failed |ret code:%d |", secretlen);
        return -1;
    }

    xqc_vec_free(&tlsref->tx_secret);
    if(xqc_vec_assign(&tlsref->tx_secret, secret, secretlen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_vec_assign  failed|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(key, sizeof(key), secret, secretlen, &tlsref-> crypto_ctx);

    if(keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_derive_packet_protection_key failed| ret code:%d|", keylen);
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret, secretlen,  &tlsref->crypto_ctx);

    if(ivlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return -1;
    }

    rv = xqc_conn_update_tx_key(conn, key, keylen, iv, ivlen);
    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_update_tx_key failed| ret code:%d|", rv);
        return -1;
    }

    secretlen = xqc_update_traffic_secret(secret, sizeof(secret), tlsref->rx_secret.base, tlsref->rx_secret.len, & tlsref->crypto_ctx);

    if(secretlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_update_traffic_secret failed| ret code:%d|", secretlen);
        return -1;
    }

    xqc_vec_free(&tlsref->rx_secret);
    if(xqc_vec_assign(&tlsref->rx_secret, secret, secretlen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_vec_assign  failed|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(key, sizeof(key), secret, secretlen, &tlsref-> crypto_ctx);

    if(keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_derive_packet_protection_key failed| ret code:%d|", keylen);
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret, secretlen,  &tlsref->crypto_ctx);

    if(ivlen < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return -1;
    }

    rv = xqc_conn_update_rx_key(conn, key, keylen, iv, ivlen);
    if(rv != 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_update_tx_key failed| ret code:%d|", rv);
        return -1;
    }

    return 0;
}

/*
 *  conn_key_phase_changed returns nonzero if |hd| indicates that the
 *  key phase has unexpected value.
 */
static int xqc_conn_key_phase_changed(xqc_connection_t *conn, const xqc_pkt_hd *hd)
{
    xqc_pktns_t *pktns = &conn->tlsref.pktns;

    // if return 1, means rx_ckm's flags is different from hd's flags
    return !(pktns->rx_ckm.flags & XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE) ^
        !(hd->flags & XQC_PKT_FLAG_KEY_PHASE);
}

int xqc_update_key(xqc_connection_t *conn, void *user_data){
    if(xqc_do_update_key(conn) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_do_update_key failed|");
        return -1;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|key update|");
    return 0;
}




/*
 *  conn_commit_key_update rotates keys.  The current key moves to old
 *  key, and new key moves to the current key.
 */
int xqc_conn_commit_key_update(xqc_connection_t *conn, uint64_t pkt_num)
{
    xqc_pktns_t *pktns = &conn->tlsref.pktns;

    xqc_tlsref_t *tlsref = & conn->tlsref;

    if(tlsref->new_tx_ckm.key.base == NULL || tlsref->new_tx_ckm.key.len == 0
            || tlsref->new_tx_ckm.iv.base == NULL || tlsref->new_tx_ckm.iv.len == 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| new key is not ready|");
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

#if 0
    ngtcp2_crypto_km_del(pktns->tx_ckm, conn->mem);
    pktns->tx_ckm = conn->new_tx_ckm;
    conn->new_tx_ckm = NULL;
    pktns->tx_ckm->pkt_num = pktns->last_tx_pkt_num + 1;// need notice
#endif
    return 0;
}

