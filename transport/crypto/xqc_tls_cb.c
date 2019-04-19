#include <stdio.h>
#include <openssl/ssl.h>
#include "xqc_tls_cb.h"
#include "xqc_tls_public.h"
#include "common/xqc_log.h"
#include "transport/xqc_conn.h"
#include "xqc_crypto.h"

/*
 * key callback
 *@param
 *@return 0 mearns error, no zero means no error
 */
int xqc_tls_key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen, void *arg)
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
            break;
        case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
            //for
            break;
        default:
            return 0;
    }

    // TODO We don't have to call this everytime we get key generated.
    if(conn->tlsref.crypto_ctx.prf == NULL){
        rv = xqc_negotiated_prf(& conn->tlsref.crypto_ctx, ssl);
        if (rv != 0) {
            return -1;
        }
    }
    if(conn->tlsref.crypto_ctx.aead == NULL){
        rv = xqc_negotiated_aead(& conn->tlsref.crypto_ctx, ssl);
        if (rv != 0) {
            return -1;
        }
    }

    uint8_t key[64] = {0}, iv[64] = {0}, hp[64] = {0}; //need check 64 bytes enough?
    size_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, secretlen, & conn->tlsref.crypto_ctx);
    if (keylen < 0) {
        return -1;
    }

    size_t ivlen = xqc_derive_packet_protection_iv(iv, sizeof(iv), secret,
            secretlen, & conn->tlsref.crypto_ctx);
    if (ivlen < 0) {
        return -1;
    }

    size_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, secretlen, & conn->tlsref.crypto_ctx);

    if (hplen < 0) {
        return -1;
    }

    // TODO Just call this once.
    xqc_conn_set_aead_overhead(conn, xqc_aead_max_overhead(& conn->tlsref.crypto_ctx));

    switch (name) {
        case SSL_KEY_CLIENT_EARLY_TRAFFIC:
            if(xqc_conn_install_early_keys(conn, key, keylen, iv, ivlen,
                        hp, hplen) < 0){
                printf("install early keys error \n");
                return -1;
            }
            break;
        case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
            if(xqc_conn_install_handshake_rx_keys(conn, key, keylen, iv,
                        ivlen, hp, hplen) < 0){
                printf("install handshake rx key error\n");
                return -1;
            }
            break;
        case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
            if(xqc_conn_install_rx_keys(conn, key, keylen, iv, ivlen,
                        hp, hplen) < 0){
                printf("install rx keys error\n");
                return -1;
            }
            break;
        case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
            if(xqc_conn_install_handshake_tx_keys(conn, key, keylen, iv,
                        ivlen, hp, hplen) < 0){
                printf("install handshake tx keys error\n");
                return -1;
            }
            break;
        case SSL_KEY_SERVER_APPLICATION_TRAFFIC:

            if(xqc_conn_install_tx_keys(conn, key, keylen, iv, ivlen,
                        hp, hplen) < 0){
                printf("install tx keys error\n");
                return -1;
            }
            break;
    }

    return 0;
}


int xqc_write_server_handshake(xqc_connection_t *conn, const void * buf, size_t buf_len){

    return 0;//need finish
}

void xqc_msg_cb(int write_p, int version, int content_type, const void *buf,
        size_t len, SSL *ssl, void *arg) {
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
            assert(len == 2);
            if (msg[0] != 2 /* FATAL */) {
                return;
            }
            //set_tls_alert(msg[1]); //need finish
            return;
        default:
            return;
    }

    rv = xqc_write_server_handshake(conn, buf, len);

    assert(0 == rv);
}

/*select aplication layer proto, now only just support XQC_ALPN_D17
 *
 */
int xqc_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
        unsigned char *outlen, const unsigned char *in,
        unsigned int inlen, void *arg) {
    xqc_connection_t * conn = (xqc_connection_t *) SSL_get_app_data(ssl) ;
    const uint8_t *alpn;
    size_t alpnlen;

    int version = conn->version ;
    // Just select alpn for now.
    switch (version) {
        case XQC_QUIC_VERSION:
            alpn = XQC_ALPN_D17;
            alpnlen = strlen(XQC_ALPN_D17);
            break;
        default:
            return SSL_TLSEXT_ERR_NOACK;
    }
    *out = (const uint8_t *)(alpn + 1);
    *outlen = alpn[0];

    return SSL_TLSEXT_ERR_OK;
}




/*
int xqc_decode_transport_params(xqc_transport_params_t *src
        )
*/

void xqc_settings_copy_from_transport_params(xqc_settings_t *dest,
                                    const xqc_transport_params_t *src) {
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
                                                const xqc_settings_t *src) {
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
}

int xqc_decode_transport_params(xqc_transport_params_t *params,
                                   uint8_t exttype, const uint8_t *data,
                                   size_t datalen) {
    //need finish
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
        const xqc_transport_params_t *params) {
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


static void conn_sync_stream_id_limit(xqc_connection_t *conn) {
    if (conn->tlsref.server) {
        conn->tlsref.max_local_stream_id_bidi =
            xqc_nth_server_bidi_id(conn->tlsref.remote_settings.max_streams_bidi);
        conn->tlsref.max_local_stream_id_bidi =
            xqc_min(conn->tlsref.max_local_stream_id_bidi, XQC_MAX_SERVER_ID_BIDI);

        conn->tlsref.max_local_stream_id_uni =
            xqc_nth_server_uni_id(conn->tlsref.remote_settings.max_streams_uni);
        conn->tlsref.max_local_stream_id_uni =
            xqc_min(conn->tlsref.max_local_stream_id_uni, XQC_MAX_SERVER_ID_UNI);
    } else {
        conn->tlsref.max_local_stream_id_bidi =
            xqc_nth_client_bidi_id(conn->tlsref.remote_settings.max_streams_bidi);
        conn->tlsref.max_local_stream_id_bidi =
            xqc_min(conn->tlsref.max_local_stream_id_bidi, XQC_MAX_CLIENT_ID_BIDI);

        conn->tlsref.max_local_stream_id_uni =
            xqc_nth_client_uni_id(conn->tlsref.remote_settings.max_streams_uni);
        conn->tlsref.max_local_stream_id_uni =
            xqc_min(conn->tlsref.max_local_stream_id_uni, XQC_MAX_CLIENT_ID_UNI);
    }
}


int xqc_conn_set_remote_transport_params(
        xqc_connection_t *conn, uint8_t exttype, const xqc_transport_params_t *params) {
    int rv;

    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            if (!conn->tlsref.server) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO At the moment, we only support one version, and there is
               no validation here. */
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if (conn->tlsref.server) {
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

    //ngtcp2_log_remote_tp(&conn->log, exttype, params);

    xqc_settings_copy_from_transport_params(&conn->tlsref.remote_settings, params);
    conn_sync_stream_id_limit(conn);

    //need finish, max_tx_offset value
    //conn->tlsref.max_tx_offset = conn->tlsref.remote_settings.max_data;

    conn->tlsref.flags |= XQC_CONN_FLAG_TRANSPORT_PARAM_RECVED;

    return 0;
}


int xqc_server_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg) {
    if (context != SSL_EXT_CLIENT_HELLO) {
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }

    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    int rv;

    xqc_transport_params_t params;

    rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, in, inlen);
    if (rv != 0) {
        printf( "xqc_decode_transport_params:%d\n",rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (rv != 0) {
        printf("xqc_conn_set_remote_transport_params:%d\n",rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }

    return 1;
}


//need finished
int xqc_conn_get_local_transport_params(xqc_connection_t *conn,
        xqc_transport_params_t *params,
        uint8_t exttype) {
    switch (exttype) {
        case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
            if (conn->tlsref.server) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO Fix this; not sure how to handle them correctly */
            params->v.ch.initial_version = conn->version;
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if (!conn->tlsref.server) {
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
    xqc_transport_params_copy_from_settings(params, &conn->tlsref.local_settings);
    if (conn->tlsref.server && (conn->tlsref.flags & XQC_CONN_FLAG_OCID_PRESENT)) {
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
        const xqc_transport_params_t *params) {
    uint8_t *p;
    size_t len = 2 /* transport parameters length */;
    size_t i;
    size_t vlen;
    /* For some reason, gcc 7.3.0 requires this initialization. */
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
                assert(params->preferred_address.ip_addresslen >= 4);
                assert(params->preferred_address.ip_addresslen < 256);
                assert(params->preferred_address.cid.cid_len == 0 ||
                        params->preferred_address.cid.cid_len >= XQC_MIN_CID_LEN);
                assert(params->preferred_address.cid.cid_len <= XQC_MAX_CID_LEN);
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

    assert((size_t)(p - dest) == len);

    return (ssize_t)len;



}


/*
   int xqc_client_transport_param_add_cb(SSL *ssl, unsigned int ext_type,
   unsigned int context, const unsigned char **out,
   size_t *outlen, X509 *x, size_t chainidx, int *al,
   void *add_arg) {
   int rv;
   xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

   xqc_transport_params_t params;
   }
   */


#define XQC_TRANSPORT_PARAM_BUF_LEN (512)
int xqc_server_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg) {
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

    size_t nwrite = xqc_encode_transport_params(
            buf, XQC_TRANSPORT_PARAM_BUF_LEN, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
            &params);
    if (nwrite < 0) {
        printf("xqc_encode_transport_params: %d\n", nwrite);
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
        void *add_arg) {
    if(out != NULL){
        free((void *)out);
    }
    return;
}


int xqc_client_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int content, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg) {
    int rv;
    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    xqc_transport_params_t params;

    rv = xqc_conn_get_local_transport_params(
            conn, &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
    if (rv != 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    size_t bufsize = 64;
    uint8_t *buf = malloc(XQC_TRANSPORT_PARAM_BUF_LEN);

    size_t nwrite = xqc_encode_transport_params(
            buf, XQC_TRANSPORT_PARAM_BUF_LEN, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (nwrite < 0) {
        printf("xqc_encode_transport_params: %d\n", nwrite);
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    *out = buf;
    *outlen = nwrite;

    return 1;
}

int xqc_client_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg) {

    xqc_connection_t * conn = (xqc_connection_t *)(SSL_get_app_data(ssl));

    int rv;

    xqc_transport_params_t params;


    rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
    if (rv != 0) {
        printf( "xqc_decode_transport_params:%d\n",rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;

    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (rv != 0) {
        printf("xqc_conn_set_remote_transport_params:%d\n",rv);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;

    }

    /*
       if (config.tp_file && write_transport_params(config.tp_file, &params) != 0) {
       std::cerr << "Could not write transport parameters in " << config.tp_file
       << std::endl;
       }*/

    return 1;
}

