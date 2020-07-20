#include "src/crypto/xqc_transport_params.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_cb.h"
// TODO 
#include "src/http3/xqc_h3_conn.h"


static
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


//need finished
static 
ssize_t xqc_encode_transport_params(uint8_t *dest, size_t destlen,
        xqc_transport_params_type_t exttype,
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

static
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

//need finished
static
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
            params->v.ch.initial_version = xqc_proto_version_value[conn->version];
            break;
        case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
            if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
                return XQC_ERR_INVALID_ARGUMENT;
            }
            /* TODO Fix this; not sure how to handle them correctly */
            params->v.ee.negotiated_version = xqc_proto_version_value[XQC_IDRAFT_VER_29];
            params->v.ee.len = 1;
            params->v.ee.supported_versions[0] = xqc_proto_version_value[XQC_IDRAFT_VER_29];

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

static
int xqc_conn_client_validate_transport_params(xqc_connection_t *conn,
        const xqc_transport_params_t *params)
{
    size_t i;

    xqc_log(conn->log, XQC_LOG_DEBUG, 
            "|xqc_conn_client_validate_transport_params|%d|%d|%d|", 
            params->v.ee.negotiated_version, 
            xqc_proto_version_value[conn->version], 
            conn->version);


    if (params->v.ee.negotiated_version != xqc_proto_version_value[conn->version]) {
        return XQC_ERR_VERSION_NEGOTIATION;
    }

    for (i = 0; i < params->v.ee.len; ++i) {
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|xqc_conn_client_validate_transport_params|%d|%d|", 
                i, params->v.ee.supported_versions[i]);

        if (params->v.ee.supported_versions[i] == xqc_proto_version_value[conn->version]) {
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

static
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

static
int xqc_decode_transport_params(xqc_transport_params_t *params,
        xqc_transport_params_type_t exttype, const uint8_t *data,
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
    ssize_t nread;

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

static
int xqc_write_transport_params(xqc_connection_t * conn,
        xqc_transport_params_t *params)
{

    char tp_buf[8192] = {0};
    int tp_data_len = snprintf(tp_buf, sizeof(tp_buf), "initial_max_streams_bidi=%"PRIu64"\n"
            "initial_max_streams_uni=%"PRIu64"\n"
            "initial_max_stream_data_bidi_local=%"PRIu64"\n"
            "initial_max_stream_data_bidi_remote=%"PRIu64"\n"
            "initial_max_stream_data_uni=%"PRIu64"\n"
            "initial_max_data=%"PRIu64"\n"
            "max_ack_delay=%"PRIu64"\n",
            params->initial_max_streams_bidi,
            params->initial_max_streams_uni,
            params->initial_max_stream_data_bidi_local,
            params->initial_max_stream_data_bidi_remote,
            params->initial_max_stream_data_uni,
            params->initial_max_data,
            params->max_ack_delay);
    if (tp_data_len == -1) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|write tp data error|ret code:%d|", tp_data_len);
        return -1;
    }
    if (conn->tlsref.save_tp_cb != NULL) {
        conn->tlsref.save_tp_cb(tp_buf, tp_data_len, xqc_conn_get_user_data(conn));
    }

    return 0;
}


// public 


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
        }else if(strncmp(p, "max_ack_delay=", strlen("max_ack_delay=")) == 0){
            p = p + strlen("max_ack_delay=");
            params->max_ack_delay = strtoul(p, NULL, 10);
        }

        p = strchr(p, '\n');
        if(p == NULL)return 0;
        p++;
    }
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

#define XQC_TRANSPORT_PARAM_BUF_LEN (512)
int 
xqc_serialize_client_transport_params(xqc_connection_t * conn, xqc_transport_params_type_t exttype,const unsigned char **out,size_t *outlen)
{
    xqc_transport_params_t params;

    int rv = xqc_conn_get_local_transport_params(conn,&params,exttype);
    if(XQC_UNLIKELY(rv != 0)) {
        return -1;
    }

    char * buf = xqc_malloc(XQC_TRANSPORT_PARAM_BUF_LEN);
    if(XQC_UNLIKELY(buf == NULL)) {
        return -1 ;
    }

    ssize_t nwrite ;
    if((nwrite = xqc_encode_transport_params(buf,XQC_TRANSPORT_PARAM_BUF_LEN,exttype,&params)) < 0) {
        xqc_free((void*)(buf));
        return -1;
    }

    *out        = buf ;
    *outlen     = nwrite ;

    return 0;
}

int 
xqc_serialize_server_transport_params(xqc_connection_t * conn, xqc_transport_params_type_t exttype,const unsigned char **out,size_t *outlen)
{
    xqc_transport_params_t params;
    int rv = xqc_conn_get_local_transport_params(
            conn, &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
    if(rv != 0) {
        return -1;
    }

    params.v.ee.len = 1;
    params.v.ee.supported_versions[0] = XQC_IDRAFT_VER_29_VALUE; 

    uint8_t *buf = xqc_malloc(XQC_TRANSPORT_PARAM_BUF_LEN);

    ssize_t nwrite = xqc_encode_transport_params(
            buf, XQC_TRANSPORT_PARAM_BUF_LEN, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
            &params);
    if(nwrite < 0) {
        xqc_free((void*)buf);
        return -1;
    }

    *out    = buf;
    *outlen = nwrite;
    return 0;
}

#undef XQC_TRANSPORT_PARAM_BUF_LEN 


int 
xqc_on_client_recv_peer_transport_params(xqc_connection_t * conn,const unsigned char *inbuf,size_t inlen)
{
    xqc_transport_params_t params;

    int rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, inbuf, inlen);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_decode_transport_params failed | ret code:%d |", rv);
        return -1;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_set_remote_transport_params failed | ret code:%d |", rv);
        return -1;
    }

    if(conn->tlsref.save_tp_cb != NULL){
        if( xqc_write_transport_params(conn, &params) < 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_transport_params failed|");
            return -1;
        }
    }

    return 0;
}


int 
xqc_on_server_recv_peer_transport_params(xqc_connection_t * conn,const unsigned char *inbuf,size_t inlen)
{
    int rv;
    xqc_transport_params_t params;

    rv = xqc_decode_transport_params(
            &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, inbuf, inlen);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_decode_transport_params | ret code :%d |", rv);
        return -1;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_conn_set_remote_transport_params | ret code :%d|", rv);
        return -1;
    }

    //save no crypto flag
    if(params.no_crypto == 1){
        conn->remote_settings.no_crypto = 1;
        conn->local_settings.no_crypto = 1;
    }
    return 0;
}


