#include <stdio.h>
#include <openssl/ssl.h>
#include "xqc_tls_cb.h"
#include "xqc_tls_public.h"
#include "common/xqc_log.h"
#include "transport/xqc_conn.h"
#include "xqc_crypto.h"
#include "xqc_tls_0rtt.h"
#include "xqc_tls_init.h"
/*
 * key callback
 *@param
 *@return 0 mearns error, no zero means no error
 */

int xqc_do_tls_key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen, void *arg)
{
    int rv;
    xqc_connection_t *conn = (xqc_connection_t *)arg;

    //printf("xqc_tls_key_cb: %d\n", name);
    //hex_print((char *)secret, secretlen);
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

    // TODO We don't have to call this everytime we get key generated.
    if(conn->tlsref.crypto_ctx.prf == NULL){
        rv = xqc_negotiated_prf(& conn->tlsref.crypto_ctx, ssl);
        if (rv != 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_negotiated_prf failed|");
            return -1;
        }
    }
    if(conn->tlsref.crypto_ctx.aead == NULL){
        rv = xqc_negotiated_aead(& conn->tlsref.crypto_ctx, ssl);
        if (rv != 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_negotiated_aead failed|");
            return -1;
        }
    }

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

    // TODO Just call this once.
    xqc_conn_set_aead_overhead(conn, xqc_aead_max_overhead(& conn->tlsref.crypto_ctx));
    if(conn->tlsref.aead_overhead < 0 || conn->tlsref.aead_overhead > XQC_INITIAL_AEAD_OVERHEAD){
        xqc_log(conn->log, XQC_LOG_ERROR, "|aead_overhead set too big| aead_overhead:%d|", conn->tlsref.aead_overhead);
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
            xqc_log(conn->log, XQC_LOG_ERROR, "|error msg_cb_handshake|");
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
            xqc_log(conn->log, XQC_LOG_ERROR, "|msg cb content_type error, may use error openssl version|content_type:%d|", content_type);
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
    const uint8_t *alpn;
    size_t alpnlen;

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

    return SSL_TLSEXT_ERR_OK;
}


void xqc_settings_copy_from_transport_params(xqc_trans_settings_t *dest,
        const xqc_transport_params_t *src)
{
    dest->max_stream_data_bidi_local = src->initial_max_stream_data_bidi_local;
    dest->max_stream_data_bidi_remote = src->initial_max_stream_data_bidi_remote;
    dest->max_stream_data_uni = src->initial_max_stream_data_uni;
    dest->max_data = src->initial_max_data;
    dest->max_streams_bidi = src->initial_max_streams_bidi;
    dest->max_streams_uni = src->initial_max_streams_uni;
    dest->idle_timeout = src->idle_timeout;
    dest->max_packet_size = src->max_packet_size;
    dest->stateless_reset_token_present = src->stateless_reset_token_present;
    if (src->stateless_reset_token_present) {
        memcpy(dest->stateless_reset_token, src->stateless_reset_token,
                sizeof(dest->stateless_reset_token));
    } else {
        memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
    }
    dest->ack_delay_exponent = src->ack_delay_exponent;
    dest->disable_migration = src->disable_migration;
    dest->max_ack_delay = src->max_ack_delay;
    dest->preferred_address = src->preferred_address;
}

void xqc_transport_params_copy_from_settings(xqc_transport_params_t *dest,
        const xqc_trans_settings_t *src)
{
    dest->initial_max_stream_data_bidi_local = src->max_stream_data_bidi_local;
    dest->initial_max_stream_data_bidi_remote = src->max_stream_data_bidi_remote;
    dest->initial_max_stream_data_uni = src->max_stream_data_uni;
    dest->initial_max_data = src->max_data;
    dest->initial_max_streams_bidi = src->max_streams_bidi;
    dest->initial_max_streams_uni = src->max_streams_uni;
    dest->idle_timeout = src->idle_timeout;
    dest->max_packet_size = src->max_packet_size;
    dest->stateless_reset_token_present = src->stateless_reset_token_present;
    if (src->stateless_reset_token_present) {
        memcpy(dest->stateless_reset_token, src->stateless_reset_token,
                sizeof(dest->stateless_reset_token));
    } else {
        memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
    }
    dest->ack_delay_exponent = src->ack_delay_exponent;
    dest->disable_migration = src->disable_migration;
    dest->max_ack_delay = src->max_ack_delay;
    dest->preferred_address = src->preferred_address;
    dest->no_crypto = src->no_crypto;
}

int xqc_decode_transport_params(xqc_transport_params_t *params,
        uint8_t exttype, const uint8_t *data,
        size_t datalen)
{
    uint32_t flags = 0;
    const uint8_t *p, *end;
    size_t supported_versionslen;
    size_t i;
    uint16_t param_type;
    size_t valuelen;
    size_t vlen;
    size_t len;
    size_t nread;

    p = data;
    end = data + datalen;

    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            if ((size_t)(end - p) < sizeof(uint32_t)) {
                return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
            }
            params->v.ch.initial_version = xqc_get_uint32(p);
            p += sizeof(uint32_t);
            vlen = sizeof(uint32_t);
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if ((size_t)(end - p) < sizeof(uint32_t) + 1) {
                return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
            }
            params->v.ee.negotiated_version = xqc_get_uint32(p);
            p += sizeof(uint32_t);
            supported_versionslen = *p++;
            if ((size_t)(end - p) < supported_versionslen ||
                    supported_versionslen % sizeof(uint32_t)) {
                return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
            }
            params->v.ee.len = supported_versionslen / sizeof(uint32_t);
            for (i = 0; i < supported_versionslen;
                    i += sizeof(uint32_t), p += sizeof(uint32_t)) {
                params->v.ee.supported_versions[i / sizeof(uint32_t)] =
                    xqc_get_uint32(p);
            }
            vlen = sizeof(uint32_t) + 1 + supported_versionslen;
            break;
        default:
            return XQC_ERR_INVALID_ARGUMENT;
    }

    if ((size_t)(end - p) < sizeof(uint16_t)) {
        return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
    }

    if (vlen + sizeof(uint16_t) + xqc_get_uint16(p) != datalen) {
        return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
    }
    p += sizeof(uint16_t);

    /* Set default values */
    params->initial_max_streams_bidi = 0;
    params->initial_max_streams_uni = 0;
    params->initial_max_stream_data_bidi_local = 0;
    params->initial_max_stream_data_bidi_remote = 0;
    params->initial_max_stream_data_uni = 0;
    params->max_packet_size = XQC_MAX_PKT_SIZE;
    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->stateless_reset_token_present = 0;
    params->preferred_address.ip_version = XQC_IP_VERSION_NONE;
    params->disable_migration = 0;
    params->max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    params->idle_timeout = 0;
    params->original_connection_id_present = 0;
    params->no_crypto = 0;

    for (; (size_t)(end - p) >= sizeof(uint16_t) * 2;) {
        param_type = xqc_get_uint16(p);
        p += sizeof(uint16_t);
        switch (param_type) {
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                flags |= 1u << param_type;
                nread =
                    xqc_decode_varint(&params->initial_max_stream_data_bidi_local, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                flags |= 1u << param_type;
                nread =
                    xqc_decode_varint(&params->initial_max_stream_data_bidi_remote, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->initial_max_stream_data_uni, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->initial_max_data, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->initial_max_streams_bidi, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->initial_max_streams_uni, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_IDLE_TIMEOUT:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->idle_timeout, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_MAX_PACKET_SIZE:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->max_packet_size, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
                if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                flags |= 1u << XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN;
                if (xqc_get_uint16(p) != sizeof(params->stateless_reset_token)) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += sizeof(uint16_t);
                if ((size_t)(end - p) < sizeof(params->stateless_reset_token)) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }

                memcpy(params->stateless_reset_token, p,
                        sizeof(params->stateless_reset_token));
                params->stateless_reset_token_present = 1;

                p += sizeof(params->stateless_reset_token);
                break;
            case XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->ack_delay_exponent, p, end);
                if (nread < 0 || params->ack_delay_exponent > 20) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            case XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS:
                if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                flags |= 1u << XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS;
                valuelen = xqc_get_uint16(p);
                p += sizeof(uint16_t);
                if ((size_t)(end - p) < valuelen) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                len = 1 /* ip_version */ + 1 /* ip_address length */ +
                    2
                    /* port */
                    + 1 /* cid length */ + XQC_STATELESS_RESET_TOKENLEN;
                if (valuelen < len) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }

                /* ip_version */
                params->preferred_address.ip_version = *p++;
                switch (params->preferred_address.ip_version) {
                    case XQC_IP_VERSION_4:
                    case XQC_IP_VERSION_6:
                        break;
                    default:
                        return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }

                /* ip_address */
                params->preferred_address.ip_addresslen = *p++;
                len += params->preferred_address.ip_addresslen;
                if (valuelen < len) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                memcpy(params->preferred_address.ip_address, p,
                        params->preferred_address.ip_addresslen);
                p += params->preferred_address.ip_addresslen;

                /* port */
                params->preferred_address.port = xqc_get_uint16(p);
                p += sizeof(uint16_t);

                /* cid */
                params->preferred_address.cid.cid_len = *p++;
                len += params->preferred_address.cid.cid_len;
                if (valuelen != len ||
                        params->preferred_address.cid.cid_len > XQC_MAX_CID_LEN ||
                        (params->preferred_address.cid.cid_len != 0 &&
                         params->preferred_address.cid.cid_len < XQC_MIN_CID_LEN)) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                if (params->preferred_address.cid.cid_len) {
                    memcpy(params->preferred_address.cid.cid_buf, p,
                            params->preferred_address.cid.cid_len);
                    p += params->preferred_address.cid.cid_len;
                }

                /* stateless reset token */
                memcpy(params->preferred_address.stateless_reset_token, p,
                        sizeof(params->preferred_address.stateless_reset_token));
                p += sizeof(params->preferred_address.stateless_reset_token);
                break;
            case XQC_TRANSPORT_PARAM_DISABLE_MIGRATION:
                flags |= 1u << XQC_TRANSPORT_PARAM_DISABLE_MIGRATION;
                if (xqc_get_uint16(p) != 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += sizeof(uint16_t);
                params->disable_migration = 1;
                break;
            case XQC_TRANSPORT_PARAM_NO_CRYPTO:
                if(xqc_get_uint16(p) != 0){
                    params->no_crypto = 1;
                }else{
                    params->no_crypto = 0;
                }
                p += sizeof(uint16_t);
                break;
            case XQC_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID:
                if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                flags |= 1u << XQC_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID;
                len = xqc_get_uint16(p);
                p += sizeof(uint16_t);
                if ((size_t)(end - p) < len) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                xqc_cid_init(&params->original_connection_id, p, len);
                params->original_connection_id_present = 1;
                p += len;
                break;
            case XQC_TRANSPORT_PARAM_MAX_ACK_DELAY:
                flags |= 1u << param_type;
                nread = xqc_decode_varint(&params->max_ack_delay, p, end);
                if (nread < 0) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += nread;
                break;
            default:
                /* Ignore unknown parameter */
                valuelen = xqc_get_uint16(p);
                p += sizeof(uint16_t);
                if ((size_t)(end - p) < valuelen) {
                    return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
                }
                p += valuelen;
                break;
        }
    }

    if (end - p != 0) {
        return XQC_ERR_MALFORMED_TRANSPORT_PARAM;
    }

    return 0;
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
int xqc_conn_client_validate_transport_params(xqc_connection_t *conn,
        const xqc_transport_params_t *params)
{
    size_t i;

    if (params->v.ee.negotiated_version != conn->version) {
        return XQC_ERR_VERSION_NEGOTIATION;
    }

    for (i = 0; i < params->v.ee.len; ++i) {
        if (params->v.ee.supported_versions[i] == conn->version) {
            break;
        }
    }

    if (i == params->v.ee.len) {
        return XQC_ERR_VERSION_NEGOTIATION;
    }

    if (conn->tlsref.flags & XQC_CONN_FLAG_RECV_RETRY) {
        /* need finish recv retry packet
           if (!params->original_connection_id_present) {
           return XQC_ERR_TRANSPORT_PARAM;
           }
           if (!xqc_cid_eq(&conn->rcid, &params->original_connection_id)) {
           return XQC_ERR_TRANSPORT_PARAM;
           }
           */
    }

    return 0;
}


int xqc_conn_set_remote_transport_params(
        xqc_connection_t *conn, uint8_t exttype, const xqc_transport_params_t *params)
{
    int rv;

    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO At the moment, we only support one version, and there is
               no validation here. */
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            rv = xqc_conn_client_validate_transport_params(conn, params);
            if (rv != 0) {
                return rv;
            }
            break;
        default:
            return XQC_ERR_INVALID_ARGUMENT;
    }

    xqc_settings_copy_from_transport_params(&conn->remote_settings, params);
    //conn_sync_stream_id_limit(conn);

    conn->tlsref.flags |= XQC_CONN_FLAG_TRANSPORT_PARAM_RECVED;

    return 0;
}

int xqc_conn_set_early_remote_transport_params(
    xqc_connection_t *conn, const xqc_transport_params_t *params)
{
  if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
    return XQC_ERR_INVALID_STATE;
  }

  xqc_settings_copy_from_transport_params(&conn->remote_settings, params);
  //conn_sync_stream_id_limit(conn);
  //conn->max_tx_offset = conn->remote_settings.max_data;

  return 0;
}


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


    int rv;

    xqc_transport_params_t params;

    rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, in, inlen);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_decode_transport_params | ret code :%d |", rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_set_remote_transport_params | ret code :%d|", rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }


    //save no crypto flag
    if(params.no_crypto == 1){
        conn->remote_settings.no_crypto = 1;
        conn->local_settings.no_crypto = 1;
    }

    return 1;
}


//need finished
int xqc_conn_get_local_transport_params(xqc_connection_t *conn,
        xqc_transport_params_t *params,
        uint8_t exttype)
{
    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO Fix this; not sure how to handle them correctly */
            params->v.ch.initial_version = conn->version;
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO Fix this; not sure how to handle them correctly */
            params->v.ee.negotiated_version = conn->version;
            params->v.ee.len = 1;
            params->v.ee.supported_versions[0] = conn->version;
            break;
        default:
            return XQC_ERR_INVALID_ARGUMENT;
    }
    xqc_transport_params_copy_from_settings(params, &conn->local_settings);
    if ((conn->conn_type == XQC_CONN_TYPE_SERVER) && (conn->tlsref.flags & XQC_CONN_FLAG_OCID_PRESENT)) {
        xqc_cid_init(&params->original_connection_id, conn->ocid.cid_buf,
                conn->ocid.cid_len);
        params->original_connection_id_present = 1;
    } else {
        params->original_connection_id_present = 0;
    }

    return 0;
}

//need finished
ssize_t xqc_encode_transport_params(uint8_t *dest, size_t destlen,
        uint8_t exttype,
        const xqc_transport_params_t *params)
{
    uint8_t *p;
    size_t len = 2 /* transport parameters length */;
    size_t i;
    size_t vlen;
    size_t preferred_addrlen = 0;

    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            vlen = sizeof(uint32_t);
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            vlen = sizeof(uint32_t) + 1 + params->v.ee.len * sizeof(uint32_t);
            if (params->stateless_reset_token_present) {
                len += 20;
            }
            if (params->preferred_address.ip_version != XQC_IP_VERSION_NONE) {
                if(params->preferred_address.ip_addresslen < 4 || params->preferred_address.ip_addresslen >= 256
                      || ( params->preferred_address.cid.cid_len != 0 && params->preferred_address.cid.cid_len < XQC_MIN_CID_LEN)
                      || params->preferred_address.cid.cid_len > XQC_MAX_CID_LEN){

                    return -1;
                }
                preferred_addrlen =
                    1 /* ip_version */ + 1 +
                    params->preferred_address.ip_addresslen /* ip_address */ +
                    2 /* port */ + 1 +
                    params->preferred_address.cid.cid_len /* connection_id */ +
                    XQC_STATELESS_RESET_TOKENLEN;
                len += 4 + preferred_addrlen;
            }
            if (params->original_connection_id_present) {
                len += 4 + params->original_connection_id.cid_len;
            }
            break;
        default:
            return XQC_ERR_INVALID_ARGUMENT;
    }

    len += vlen;

    if (params->initial_max_stream_data_bidi_local) {
        len +=
            4 + xqc_put_varint_len(params->initial_max_stream_data_bidi_local);
    }
    if (params->initial_max_stream_data_bidi_remote) {
        len +=
            4 + xqc_put_varint_len(params->initial_max_stream_data_bidi_remote);
    }
    if (params->initial_max_stream_data_uni) {
        len += 4 + xqc_put_varint_len(params->initial_max_stream_data_uni);
    }
    if (params->initial_max_data) {
        len += 4 + xqc_put_varint_len(params->initial_max_data);
    }
    if (params->initial_max_streams_bidi) {
        len += 4 + xqc_put_varint_len(params->initial_max_streams_bidi);
    }
    if (params->initial_max_streams_uni) {
        len += 4 + xqc_put_varint_len(params->initial_max_streams_uni);
    }
    if (params->max_packet_size != XQC_MAX_PKT_SIZE) {
        len += 4 + xqc_put_varint_len(params->max_packet_size);
    }
    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        len += 4 + xqc_put_varint_len(params->ack_delay_exponent);
    }
    if (params->disable_migration) {
        len += 4;
    }
    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        len += 4 + xqc_put_varint_len(params->max_ack_delay);
    }
    if (params->idle_timeout) {
        len += 4 + xqc_put_varint_len(params->idle_timeout);
    }
    if( params->no_crypto){
        len += 4;
    }

    if (destlen < len) {
        return XQC_ERR_NOBUF;
    }

    p = dest;

    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            p = xqc_put_uint32be(p, params->v.ch.initial_version);
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            p = xqc_put_uint32be(p, params->v.ee.negotiated_version);
            *p++ = (uint8_t)(params->v.ee.len * sizeof(uint32_t));
            for (i = 0; i < params->v.ee.len; ++i) {
                p = xqc_put_uint32be(p, params->v.ee.supported_versions[i]);
            }
            break;
    }

    p = xqc_put_uint16be(p, (uint16_t)(len - vlen - sizeof(uint16_t)));

    if (exttype == XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        if (params->stateless_reset_token_present) {
            p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
            p = xqc_put_uint16be(p, sizeof(params->stateless_reset_token));
            p = xqc_cpymem(p, params->stateless_reset_token,
                    sizeof(params->stateless_reset_token));
        }
        if (params->preferred_address.ip_version != XQC_IP_VERSION_NONE) {
            p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS);
            p = xqc_put_uint16be(p, (uint16_t)preferred_addrlen);
            *p++ = params->preferred_address.ip_version;
            *p++ = (uint8_t)params->preferred_address.ip_addresslen;
            p = xqc_cpymem(p, params->preferred_address.ip_address,
                    params->preferred_address.ip_addresslen);
            p = xqc_put_uint16be(p, params->preferred_address.port);
            *p++ = (uint8_t)params->preferred_address.cid.cid_len;
            if (params->preferred_address.cid.cid_len) {
                p = xqc_cpymem(p, params->preferred_address.cid.cid_buf,
                        params->preferred_address.cid.cid_len);
            }
            p = xqc_cpymem(
                    p, params->preferred_address.stateless_reset_token,
                    sizeof(params->preferred_address.stateless_reset_token));
        }
        if (params->original_connection_id_present) {
            p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID);
            p = xqc_put_uint16be(p,
                    (uint16_t)params->original_connection_id.cid_len);
            p = xqc_cpymem(p, params->original_connection_id.cid_buf,
                    params->original_connection_id.cid_len);
        }
    }

    if (params->initial_max_stream_data_bidi_local) {
        p = xqc_put_uint16be(
                p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
        p = xqc_put_uint16be(p, (uint16_t)xqc_put_varint_len(
                    params->initial_max_stream_data_bidi_local));
        p = xqc_put_varint(p, params->initial_max_stream_data_bidi_local);
    }

    if (params->initial_max_stream_data_bidi_remote) {
        p = xqc_put_uint16be(
                p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
        p = xqc_put_uint16be(p,
                (uint16_t)xqc_put_varint_len(
                    params->initial_max_stream_data_bidi_remote));
        p = xqc_put_varint(p, params->initial_max_stream_data_bidi_remote);
    }

    if (params->initial_max_stream_data_uni) {
        p = xqc_put_uint16be(p,
                XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI);
        p = xqc_put_uint16be(p, (uint16_t)xqc_put_varint_len(
                    params->initial_max_stream_data_uni));
        p = xqc_put_varint(p, params->initial_max_stream_data_uni);
    }

    if (params->initial_max_data) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->initial_max_data));
        p = xqc_put_varint(p, params->initial_max_data);
    }

    if (params->initial_max_streams_bidi) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->initial_max_streams_bidi));
        p = xqc_put_varint(p, params->initial_max_streams_bidi);
    }

    if (params->initial_max_streams_uni) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->initial_max_streams_uni));
        p = xqc_put_varint(p, params->initial_max_streams_uni);
    }

    if (params->max_packet_size != XQC_MAX_PKT_SIZE) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_MAX_PACKET_SIZE);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->max_packet_size));
        p = xqc_put_varint(p, params->max_packet_size);
    }

    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->ack_delay_exponent));
        p = xqc_put_varint(p, params->ack_delay_exponent);
    }

    if (params->disable_migration) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_DISABLE_MIGRATION);
        p = xqc_put_uint16be(p, 0);
    }

    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_MAX_ACK_DELAY);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->max_ack_delay));
        p = xqc_put_varint(p, params->max_ack_delay);
    }

    if (params->idle_timeout) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_IDLE_TIMEOUT);
        p = xqc_put_uint16be(
                p, (uint16_t)xqc_put_varint_len(params->idle_timeout));
        p = xqc_put_varint(p, params->idle_timeout);
    }

    if (params->no_crypto) {
        p = xqc_put_uint16be(p, XQC_TRANSPORT_PARAM_NO_CRYPTO);
        p = xqc_put_uint16be(p, 1);
    }


    if((size_t)(p - dest) != len){
        return -1;
    }

    return (ssize_t)len;
}


#define XQC_TRANSPORT_PARAM_BUF_LEN (512)
int xqc_server_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg)
{
    int rv;
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    xqc_transport_params_t params;

    rv = xqc_conn_get_local_transport_params(
            conn, &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
    if (rv != 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    params.v.ee.len = 1;
    params.v.ee.supported_versions[0] = XQC_QUIC_VERSION; // just use XQC VERSION

    uint8_t *buf = malloc(XQC_TRANSPORT_PARAM_BUF_LEN);

    ssize_t nwrite = xqc_encode_transport_params(
            buf, XQC_TRANSPORT_PARAM_BUF_LEN, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
            &params);
    if (nwrite < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_encode_transport_params failed | ret code:%d|", nwrite);

        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    *out = buf;
    *outlen = nwrite;

    return 1;
}

//need finish , need test for malloc free
void xqc_transport_params_free_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *out,
        void *add_arg)
{
    if(out != NULL){
        free((void *)out);
    }
    return;
}


int xqc_client_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int content, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg)
{
    int rv;
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    xqc_transport_params_t params;

    rv = xqc_conn_get_local_transport_params(
            conn, &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
    if (rv != 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    uint8_t *buf = malloc(XQC_TRANSPORT_PARAM_BUF_LEN);

    ssize_t nwrite = xqc_encode_transport_params(
            buf, XQC_TRANSPORT_PARAM_BUF_LEN, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (nwrite < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_encode_transport_params | ret code:%d |", nwrite);
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    *out = buf;
    *outlen = nwrite;

    return 1;
}


int xqc_write_transport_params(xqc_connection_t * conn,
        xqc_transport_params_t *params)
{

    char tp_buf[8192] = {0};
    int tp_data_len = snprintf(tp_buf, sizeof(tp_buf), "initial_max_streams_bidi=%d\n"
            "initial_max_streams_uni=%d\n"
            "initial_max_stream_data_bidi_local=%d\n"
            "initial_max_stream_data_bidi_remote=%d\n"
            "initial_max_stream_data_uni=%d\n"
            "initial_max_data=%d\n",
            params->initial_max_streams_bidi,
            params->initial_max_streams_uni,
            params->initial_max_stream_data_bidi_local,
            params->initial_max_stream_data_bidi_remote,
            params->initial_max_stream_data_uni,
            params->initial_max_data);
    if(tp_data_len == -1){
        xqc_log(conn->log, XQC_LOG_ERROR, "| write tp data error | ret code:%d |", tp_data_len);
        return -1;
    }
    if(conn -> tlsref.save_tp_cb != NULL){
        if(conn -> tlsref.save_tp_cb(tp_buf, tp_data_len, conn->tlsref.tp_user_data) < 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "| save tp data error |");
            return -1;
        }
    }

    return 0;
}

int xqc_client_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg)
{
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    int rv;

    xqc_transport_params_t params;

    rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_decode_transport_params failed | ret code:%d |", rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;

    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_set_remote_transport_params failed | ret code:%d |", rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;

    }

    if(conn->tlsref.save_tp_cb != NULL){
        if( xqc_write_transport_params(conn, &params) < 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_transport_params failed|");
            return -1;
        }
    }

    return 1;
}


int xqc_read_transport_params(char * tp_data, size_t tp_data_len, xqc_transport_params_t *params)
{

    if(strlen(tp_data) != tp_data_len){
        tp_data[tp_data_len] = '\0';
    }
    char * p = tp_data;
    while(*p != '\0'){
        if( *p == ' ')p++;
        if(strncmp( p , "initial_max_streams_bidi=", strlen("initial_max_streams_bidi=")) == 0){
            p = p + strlen("initial_max_streams_bidi=");
            params->initial_max_streams_bidi = strtoul(p, NULL, 10);
        }else if(strncmp(p, "initial_max_streams_uni=", strlen("initial_max_streams_uni=")) == 0){
            p = p+strlen("initial_max_streams_uni=");
            params->initial_max_streams_uni = strtoul(p, NULL, 10);
        }else if(strncmp(p, "initial_max_stream_data_bidi_local=", strlen("initial_max_stream_data_bidi_local=")) == 0){
            p = p+strlen("initial_max_stream_data_bidi_local=");
            params->initial_max_stream_data_bidi_local = strtoul(p, NULL, 10);
        }else if(strncmp(p, "initial_max_stream_data_bidi_remote=", strlen("initial_max_stream_data_bidi_remote=")) == 0){
            p = p + strlen("initial_max_stream_data_bidi_remote=");
            params->initial_max_stream_data_bidi_remote = strtoul(p, NULL, 10);
        }else if(strncmp(p, "initial_max_stream_data_uni=", strlen("initial_max_stream_data_uni=")) == 0){
            p = p + strlen("initial_max_stream_data_uni=");
            params->initial_max_stream_data_uni = strtoul(p, NULL, 10);
        }else if(strncmp(p, "initial_max_data=", strlen("initial_max_data=")) == 0){
            p = p + strlen("initial_max_data=");
            params->initial_max_data = strtoul(p, NULL, 10);
        }else{
            continue;
        }
        p = strchr(p, '\n');
        if(p == NULL)return 0;
        p++;
    }
    return 0;
}


int xqc_do_update_key(xqc_connection_t *conn)
{

    char secret[64], key[64], iv[64];
    //conn->tlsref.nkey_update++;
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
    (void *)user_data;
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

