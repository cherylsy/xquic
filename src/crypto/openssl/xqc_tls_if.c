#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_stack_cb.h"
#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_transport_params.h"

static int
xqc_server_tls_handshake(xqc_connection_t * conn)
{
    int rv = 0;
    SSL *ssl = conn->xc_ssl;
    
    /* SSL_do_handshake return 1 means handshake complete, 
     * 0 means should check error code,
     * <0 means a fatal error, check error code to get detail information.
     */
    rv = SSL_do_handshake(ssl);
    if (rv <= 0) {
        int err = SSL_get_error(ssl, rv);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return XQC_OK;
        case SSL_ERROR_SSL:
            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|",
                    ERR_error_string(ERR_get_error(), NULL));
            return XQC_ERROR;
        default:
            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|",
                    ERR_error_string(ERR_get_error(), NULL));
            return XQC_ERROR;
        }
    }

    if (xqc_conn_handshake_completed(conn) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "|TLS handshake error: handshake completed callback return error|");
        return XQC_ERROR;
    }
    return XQC_OK;

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
                return -XQC_ERR_PROTO;
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
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS read error:%s|",
                        ERR_error_string(ERR_get_error(), NULL));
                return -XQC_ERR_CRYPTO;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS read error:%s|",
                        ERR_error_string(ERR_get_error(), NULL));
                return -XQC_ERR_CRYPTO;
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

static int
xqc_client_tls_handshake(xqc_connection_t *conn)
{
    int rv;
    SSL *ssl = conn->xc_ssl;
    ERR_clear_error();

    if (conn->tlsref.initial && conn->tlsref.resumption 
        && SSL_SESSION_get_max_early_data(SSL_get_session(ssl))) {
        conn->tlsref.initial = 0;
    }
    rv = SSL_do_handshake(ssl);
    if (rv <= 0) {
        int err = SSL_get_error(ssl, rv);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return XQC_OK;
        case SSL_ERROR_SSL:
            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|",
                    ERR_error_string(ERR_get_error(), NULL));
            return XQC_ERROR;
        default:
            xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|",
                    ERR_error_string(ERR_get_error(), NULL));
            return XQC_ERROR;
        }
    }

    const uint8_t *peer_transport_params;
    size_t outlen;
    SSL_get_peer_quic_transport_params(ssl, &peer_transport_params, &outlen);

    if (XQC_LIKELY(outlen > 0)) {
        int ret = xqc_on_client_recv_peer_transport_params(conn, peer_transport_params, outlen);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|client receive perr transport parameter error, ret:%d|", ret);
            return XQC_ERROR;
        }
    }

    if (xqc_conn_handshake_completed(conn) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|handshake callback return error|");
        return XQC_ERROR;
    }
    return XQC_OK;
}

static enum
ssl_encryption_level_t xqc_convert_to_bssl_level(xqc_encrypt_level_t level)
{
    switch (level) {
    case XQC_ENC_LEV_INIT:
        return ssl_encryption_initial;
    case XQC_ENC_LEV_0RTT:
        return ssl_encryption_early_data;
    case XQC_ENC_LEV_HSK:
        return ssl_encryption_handshake;
    case XQC_ENC_LEV_1RTT:
    default:
        return ssl_encryption_application;
    }
}

int
xqc_recv_crypto_data_cb(xqc_connection_t *conn,
    uint64_t offset, const uint8_t *data, size_t datalen,
    xqc_encrypt_level_t encrypt_level, void *user_data)
{
    SSL *ssl = conn->xc_ssl;
    if (SSL_provide_quic_data(ssl, xqc_convert_to_bssl_level(encrypt_level), 
                data, datalen) != XQC_SSL_SUCCESS) {
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "| SSL_provide_quic_data failed[level:%d]|", encrypt_level);
        return XQC_ERROR;
    }

    if (xqc_conn_get_handshake_completed(conn) == XQC_OK) {
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            if (xqc_server_tls_handshake(conn) != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|error server handshake|");
                return XQC_ERROR;
            }

        } else {
            if (xqc_client_tls_handshake(conn) != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|error client handshake|");
                return XQC_ERROR;
            }
        }

    } else {
        if (SSL_process_quic_post_handshake(ssl) != XQC_SSL_SUCCESS) {
            xqc_log(conn->log, XQC_LOG_ERROR, "| SSL_process_quic_post_handshake failed |");
            return XQC_ERROR;
        }
    }

    return XQC_OK;
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


int xqc_recv_client_initial_cb(xqc_connection_t * conn,
        xqc_cid_t *dcid,
        void *user_data)
{
    return xqc_recv_client_hello_derive_key(conn, dcid);
}

#ifdef XQC_PRINT_SECRET
static void
xqc_tls_print_secret(SSL *ssl, xqc_connection_t *conn, enum ssl_encryption_level_t level,
                    const unsigned char *read_secret, const unsigned char *write_secret, size_t secretlen)
{
    if (strlen((const char*)conn->client_ramdom_hex) == 0) {
        unsigned char client_random[33] = {0};
        size_t out_len = 32;
        out_len = SSL_get_client_random(ssl, client_random, out_len);
        xqc_hex_dump(conn->client_ramdom_hex, client_random, out_len);
    }

    if (level == ssl_encryption_early_data) {
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            xqc_hex_dump(conn->secret_hex[CLIENT_EARLY_TRAFFIC_SECRET], write_secret, secretlen);
        }
    } else if (level == ssl_encryption_handshake) {
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            xqc_hex_dump(conn->secret_hex[CLIENT_HANDSHAKE_TRAFFIC_SECRET], write_secret, secretlen);
            xqc_hex_dump(conn->secret_hex[SERVER_HANDSHAKE_TRAFFIC_SECRET], read_secret, secretlen);
        }
    } else if (level == ssl_encryption_application) {
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            xqc_hex_dump(conn->secret_hex[CLIENT_TRAFFIC_SECRET_0], write_secret, secretlen);
            xqc_hex_dump(conn->secret_hex[SERVER_TRAFFIC_SECRET_0], read_secret, secretlen);
        }
    }
}
#endif

static int
xqc_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *read_secret, const uint8_t *write_secret, size_t secret_len)
{
    xqc_connection_t *conn = (xqc_connection_t *) SSL_get_app_data(ssl);

#ifdef XQC_PRINT_SECRET
    xqc_tls_print_secret(ssl, conn, level, read_secret, write_secret, secret_len);
#endif

    int rv = 0;
    /* call it every time */
    xqc_init_crypto_ctx(conn, SSL_get_current_cipher(ssl));


#define XQC_MAX_KNP_LEN  64
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0},
            hp[XQC_MAX_KNP_LEN] = {0};
    size_t keylen = XQC_MAX_KNP_LEN, ivlen = XQC_MAX_KNP_LEN,
           hplen = XQC_MAX_KNP_LEN;
#undef XQC_MAX_KNP_LEN
    switch (level) {
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx,
                                              read_secret, secret_len, key,
                                              &keylen, iv, &ivlen, hp,
                                              &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }

            if (xqc_conn_install_early_keys(conn, key, keylen, iv, ivlen, hp, hplen)
                != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|install early keys error|");
                return XQC_SSL_FAIL;
            }
            break;

        } else {
            if (conn->local_settings.no_crypto == 1) {
                /* 更新client明文模式下的加密函数 */
                xqc_negotiated_aead_and_prf(&conn->tlsref.crypto_ctx, NID_undef);  
            }

            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx, write_secret,
                                              secret_len, key, &keylen, iv, &ivlen,
                                              hp, &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }

            if (xqc_conn_install_early_keys(conn, key, keylen, iv, ivlen, hp, hplen)
                != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|install early keys error|");
                return XQC_SSL_FAIL;
            }
            break;
        }

    case ssl_encryption_handshake:
        if (read_secret != NULL) {
            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx, read_secret,
                                              secret_len, key, &keylen, iv, &ivlen, 
                                              hp, &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }

            if (xqc_conn_install_handshake_rx_keys(conn, key, keylen, iv, ivlen, hp,
                                                   hplen) != XQC_OK) {
                return XQC_SSL_FAIL;
            }
        }
        if (write_secret != NULL) {
            if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
                const uint8_t *peer_transport_params = NULL;
                size_t outlen = 0;
                SSL_get_peer_quic_transport_params(ssl, &peer_transport_params, &outlen);


                if (XQC_LIKELY(outlen > 0)) {
                    int ret = xqc_on_server_recv_peer_transport_params(conn, 
                            peer_transport_params, outlen);
                    if (ret != XQC_OK) {
                        xqc_log(conn->log, XQC_LOG_ERROR,
                                "|server receive perr transport parameter error, ret:%d|", ret);
                        return XQC_SSL_FAIL;
                    }
                }
            }
            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx, write_secret,
                                              secret_len, key, &keylen, iv, &ivlen, 
                                              hp, &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }
            if (xqc_conn_install_handshake_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) 
                != XQC_OK) {
                return XQC_SSL_FAIL;
            }
        }

        if (conn->local_settings.no_crypto == 1) {
            /* 更新明文模式下的加密函数 */
            xqc_negotiated_aead_and_prf(&conn->tlsref.crypto_ctx, NID_undef);  
        }

        break;
    case ssl_encryption_application:
        if (read_secret != NULL) {
            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx, read_secret,
                                              secret_len, key, &keylen, iv, &ivlen, 
                                              hp, &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }

            if (xqc_conn_install_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen)
                != XQC_OK) {
                return XQC_SSL_FAIL;
            }
        }
        if (write_secret != NULL) {
            rv = xqc_derive_packet_protection(&conn->tlsref.crypto_ctx, write_secret,
                                              secret_len, key, &keylen, iv, &ivlen, 
                                              hp, &hplen, conn->log);
            if (rv != XQC_SSL_SUCCESS) {
                return XQC_SSL_FAIL;
            }
            if (xqc_conn_install_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) 
                != XQC_OK) {
                return XQC_SSL_FAIL;
            }
        }
        break;
    }
    return XQC_SSL_SUCCESS;
}

int
xqc_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                            const uint8_t *data, size_t len)
{
    xqc_connection_t *conn = (xqc_connection_t *) SSL_get_app_data(ssl);
    xqc_pktns_t *pktns = NULL;

    switch (level) {
    case ssl_encryption_initial:
        pktns = &conn->tlsref.initial_pktns;
        break;
    case ssl_encryption_early_data:
        // 不会有这个等级的数据
        return XQC_SSL_FAIL;
    case ssl_encryption_handshake:
        pktns = &conn->tlsref.hs_pktns;
        break;
    case ssl_encryption_application:
        pktns = &conn->tlsref.pktns;
        break;
    default:
        /* no way, in case of new level */
        return XQC_SSL_FAIL;
    }

    xqc_hs_buffer_t *p_data = xqc_create_hs_buffer(len);
    if (XQC_UNLIKELY(!p_data)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_hs_buffer failed|");
        return XQC_SSL_FAIL;
    }

    memcpy(p_data->data, data, len);
    xqc_list_add_tail(&p_data->list_head, &pktns->msg_cb_head);
    return XQC_SSL_SUCCESS;
}

int
xqc_flush_flight(SSL *ssl)
{
    return XQC_SSL_SUCCESS;
}

int
xqc_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    return XQC_SSL_SUCCESS;
}

SSL_QUIC_METHOD xqc_ssl_quic_method = {
    .set_encryption_secrets = xqc_set_encryption_secrets,
    .add_handshake_data     = xqc_add_handshake_data,
    .flush_flight           = xqc_flush_flight,
    .send_alert             = xqc_send_alert,
};
