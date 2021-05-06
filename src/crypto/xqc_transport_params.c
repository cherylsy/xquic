#include "src/crypto/xqc_transport_params.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/common/xqc_variable_len_int.h"


#define XQC_PREFERRED_ADDR_IPV4_LEN         4
#define XQC_PREFERRED_ADDR_IPV4_PORT_LEN    2
#define XQC_PREFERRED_ADDR_IPV6_LEN         16
#define XQC_PREFERRED_ADDR_IPV6_PORT_LEN    2


static void 
xqc_transport_params_copy_from_settings(xqc_transport_params_t *dest,
    const xqc_trans_settings_t *src)
{
    dest->initial_max_stream_data_bidi_local = src->max_stream_data_bidi_local;
    dest->initial_max_stream_data_bidi_remote = src->max_stream_data_bidi_remote;
    dest->initial_max_stream_data_uni = src->max_stream_data_uni;
    dest->initial_max_data = src->max_data;
    dest->initial_max_streams_bidi = src->max_streams_bidi;
    dest->initial_max_streams_uni = src->max_streams_uni;
    dest->max_idle_timeout = src->max_idle_timeout;
    dest->max_udp_payload_size = src->max_udp_payload_size;
    dest->stateless_reset_token_present = src->stateless_reset_token_present;
    if (src->stateless_reset_token_present) {
        memcpy(dest->stateless_reset_token, src->stateless_reset_token,
              sizeof(dest->stateless_reset_token));
    } else {
        memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
    }
    dest->ack_delay_exponent = src->ack_delay_exponent;
    dest->disable_active_migration = src->disable_active_migration;
    dest->max_ack_delay = src->max_ack_delay;
    dest->preferred_address = src->preferred_address;
    dest->active_connection_id_limit = src->active_connection_id_limit;
    dest->no_crypto = src->no_crypto;
    dest->enable_multipath = src->enable_multipath;
}


static ssize_t 
xqc_transport_params_calc_length(xqc_transport_params_type_t exttype,
    const xqc_transport_params_t *params) 
{
    size_t len = 0;
    size_t preferred_addrlen = 0;

    if (params->original_dest_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID) +
               xqc_put_varint_len(params->original_dest_connection_id.cid_len) + 
               params->original_dest_connection_id.cid_len;
    }

    if (params->max_idle_timeout) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_idle_timeout)) +
               xqc_put_varint_len(params->max_idle_timeout);
    }

    if (XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS == exttype 
        && params->stateless_reset_token_present) 
    {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN) +
               xqc_put_varint_len(XQC_STATELESS_RESET_TOKENLEN) + 
               XQC_STATELESS_RESET_TOKENLEN;
    }

    if (params->max_udp_payload_size != XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_udp_payload_size)) +
               xqc_put_varint_len(params->max_udp_payload_size);
    }

    if (params->initial_max_data) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_data)) +
               xqc_put_varint_len(params->initial_max_data);
    }

    if (params->initial_max_stream_data_bidi_local) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_bidi_local)) +
               xqc_put_varint_len(params->initial_max_stream_data_bidi_local);
    }

    if (params->initial_max_stream_data_bidi_remote) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_bidi_remote)) +
               xqc_put_varint_len(params->initial_max_stream_data_bidi_remote);
    }

    if (params->initial_max_stream_data_uni) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_uni)) +
               xqc_put_varint_len(params->initial_max_stream_data_uni);
    }

    if (params->initial_max_streams_bidi) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_streams_bidi)) +
               xqc_put_varint_len(params->initial_max_streams_bidi);
    }

    if (params->initial_max_streams_uni) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_streams_uni)) +
               xqc_put_varint_len(params->initial_max_streams_uni);
    }

    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT) + 
               xqc_put_varint_len(xqc_put_varint_len(params->ack_delay_exponent)) +
               xqc_put_varint_len(params->ack_delay_exponent);
    }

    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_ACK_DELAY) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_ack_delay)) +
               xqc_put_varint_len(params->max_ack_delay);
    }

    if (params->disable_active_migration) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) + 
               xqc_put_varint_len(0);   /* disable_active_migration is zero-length transport parameter */
    }

    /* PREFERRED_ADDRESS */
    if (exttype == XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS 
        && params->preferred_address_present
        && params->preferred_address.cid.cid_len > 0)
    {
        preferred_addrlen = sizeof(params->preferred_address.ipv4) + 
                            sizeof(params->preferred_address.ipv4_port) + 
                            sizeof(params->preferred_address.ipv6) + 
                            sizeof(params->preferred_address.ipv6_port) +
                            sizeof(params->preferred_address.cid.cid_len) + 
                            params->preferred_address.cid.cid_len +
                            sizeof(params->preferred_address.stateless_reset_token);

        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS) +
             xqc_put_varint_len(preferred_addrlen) + preferred_addrlen;
    }

    if (params->active_connection_id_limit != XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT) +
               xqc_put_varint_len(xqc_put_varint_len(params->active_connection_id_limit)) +
               xqc_put_varint_len(params->active_connection_id_limit);
    }

    if (params->initial_source_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID) +
               xqc_put_varint_len(params->initial_source_connection_id.cid_len) + 
               params->initial_source_connection_id.cid_len;
    }

    if (params->retry_source_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID) +
               xqc_put_varint_len(params->retry_source_connection_id.cid_len) + 
               params->retry_source_connection_id.cid_len;
    }

    if (params->no_crypto) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_NO_CRYPTO) +
               xqc_put_varint_len(xqc_put_varint_len(params->no_crypto)) +
               xqc_put_varint_len(params->no_crypto);
    }

    if (params->enable_multipath) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH) +
               xqc_put_varint_len(xqc_put_varint_len(params->enable_multipath)) +
               xqc_put_varint_len(params->enable_multipath);
    }

    return len;
}


/**
 * put variant int value param into buf
 */
inline static uint8_t*
xqc_put_varint_param(uint8_t* p, xqc_transport_param_id_t id, uint64_t v)
{
    p = xqc_put_varint(p, id);
    p = xqc_put_varint(p, xqc_put_varint_len(v));
    p = xqc_put_varint(p, v);
    return p;
}

/**
 * put zero-length value param into buf
 */
inline static uint8_t*
xqc_put_zero_length_param(uint8_t* p, xqc_transport_param_id_t id)
{
    p = xqc_put_varint(p, id);  // put id
    p = xqc_put_varint(p, 0);   // put length, which is 0
    return p;
}


static ssize_t 
xqc_encode_transport_params(uint8_t *dest, size_t destlen,
    xqc_transport_params_type_t exttype,
    const xqc_transport_params_t *params) 
{
    uint8_t *p = dest;
    size_t len = 0;
    size_t preferred_addrlen = 0;

    /* calculate encoding length */
    len += xqc_transport_params_calc_length(exttype, params);
    if (destlen < len) {
        return -XQC_TLS_NOBUF;
    }

    /* start writing */
    /* write transport parameter buffer len */
    if (params->original_dest_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID);
        p = xqc_put_varint(p, params->original_dest_connection_id.cid_len);
        p = xqc_cpymem(p, params->original_dest_connection_id.cid_buf,
                       params->original_dest_connection_id.cid_len);
    }

    if (params->max_idle_timeout) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT, 
                                 params->max_idle_timeout);
    }

    if (XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS == exttype 
        && params->stateless_reset_token_present) 
    {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
        p = xqc_put_varint(p, XQC_STATELESS_RESET_TOKENLEN);
        p = xqc_cpymem(p, params->stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN);
    }

    if (params->max_udp_payload_size != XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE, 
                                 params->max_udp_payload_size);
    }

    if (params->initial_max_data) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA, 
                                 params->initial_max_data);
    }

    if (params->initial_max_stream_data_bidi_local) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                 params->initial_max_stream_data_bidi_local);
    }

    if (params->initial_max_stream_data_bidi_remote) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                 params->initial_max_stream_data_bidi_remote);
    }

    if (params->initial_max_stream_data_uni) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
                                 params->initial_max_stream_data_uni);
    }

    if (params->initial_max_streams_bidi) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
                                 params->initial_max_streams_bidi);
    }

    if (params->initial_max_streams_uni) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
                                 params->initial_max_streams_uni);
    }

    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                                 params->ack_delay_exponent);
    }

    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_ACK_DELAY,
                                 params->max_ack_delay);
    }

    if (params->disable_active_migration) {
        p = xqc_put_zero_length_param(p, XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION);
    }

    if (exttype == XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS 
        && params->preferred_address_present
        && params->preferred_address.cid.cid_len > 0)   /* cid MUST NOT be zero-length */
    {
        preferred_addrlen = sizeof(params->preferred_address.ipv4) + 
                            sizeof(params->preferred_address.ipv4_port) + 
                            sizeof(params->preferred_address.ipv6) + 
                            sizeof(params->preferred_address.ipv6_port) +
                            sizeof(params->preferred_address.cid.cid_len) + 
                            params->preferred_address.cid.cid_len +
                            sizeof(params->preferred_address.stateless_reset_token);

        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS);
        p = xqc_put_varint(p, preferred_addrlen);
        p = xqc_cpymem(p, params->preferred_address.ipv4, sizeof(params->preferred_address.ipv4));
        p = xqc_put_uint16be(p, params->preferred_address.ipv4_port);
        p = xqc_cpymem(p, params->preferred_address.ipv6, sizeof(params->preferred_address.ipv6));
        p = xqc_put_uint16be(p, params->preferred_address.ipv6_port);
        *p++ = params->preferred_address.cid.cid_len;
        p = xqc_cpymem(p, params->preferred_address.cid.cid_buf, params->preferred_address.cid.cid_len);
        p = xqc_cpymem(p, params->preferred_address.stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN);
    }

    if (params->active_connection_id_limit != XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                                 params->active_connection_id_limit);
    }

    if (params->initial_source_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID);
        p = xqc_put_varint(p, params->initial_source_connection_id.cid_len);
        p = xqc_cpymem(p, params->initial_source_connection_id.cid_buf, params->initial_source_connection_id.cid_len);
    }

    if (params->retry_source_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID);
        p = xqc_put_varint(p, params->retry_source_connection_id.cid_len);
        p = xqc_cpymem(p, params->retry_source_connection_id.cid_buf, params->retry_source_connection_id.cid_len);
    }

    if (params->no_crypto) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_NO_CRYPTO,
                                 params->no_crypto);
    }

    if (params->enable_multipath) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH,
                                 params->enable_multipath);
    }

    if ((size_t)(p - dest) != len) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    return (ssize_t)len;
}


static void 
xqc_settings_copy_from_transport_params(xqc_trans_settings_t *dest,
    const xqc_transport_params_t *src)
{
    dest->max_stream_data_bidi_local = src->initial_max_stream_data_bidi_local;
    dest->max_stream_data_bidi_remote = src->initial_max_stream_data_bidi_remote;
    dest->max_stream_data_uni = src->initial_max_stream_data_uni;
    dest->max_data = src->initial_max_data;
    dest->max_streams_bidi = src->initial_max_streams_bidi;
    dest->max_streams_uni = src->initial_max_streams_uni;
    dest->max_idle_timeout = src->max_idle_timeout;
    dest->max_udp_payload_size = src->max_udp_payload_size;
    dest->stateless_reset_token_present = src->stateless_reset_token_present;

    if (src->stateless_reset_token_present) {
        xqc_memcpy(dest->stateless_reset_token, src->stateless_reset_token,
                   sizeof(dest->stateless_reset_token));

    } else {
        xqc_memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
    }

    dest->ack_delay_exponent = src->ack_delay_exponent;
    dest->disable_active_migration = src->disable_active_migration;
    dest->max_ack_delay = src->max_ack_delay;
    dest->preferred_address = src->preferred_address;
    dest->active_connection_id_limit = src->active_connection_id_limit;

    dest->enable_multipath = src->enable_multipath;
}

//need finished
static xqc_int_t 
xqc_conn_get_local_transport_params(xqc_connection_t *conn,
    xqc_transport_params_t *params, uint8_t exttype)
{
    switch (exttype) {
    case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        break;

    case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
        if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        break;

    default:
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    xqc_transport_params_copy_from_settings(params, &conn->local_settings);
    if (conn->conn_type == XQC_CONN_TYPE_SERVER 
        && conn->ocid.cid_len > 0) 
    {
        xqc_cid_init(&params->original_dest_connection_id, conn->ocid.cid_buf,
                     conn->ocid.cid_len);
        params->original_dest_connection_id_present = 1;

    } else {
        params->original_dest_connection_id_present = 0;
    }

    xqc_cid_init(&params->initial_source_connection_id, 
                 conn->scid.cid_buf, conn->scid.cid_len);
    params->initial_source_connection_id_present = 1;

    params->retry_source_connection_id.cid_len = 0;
    params->retry_source_connection_id_present = 0;

    return XQC_OK;
}


static int 
xqc_conn_client_validate_transport_params(xqc_connection_t *conn,
    const xqc_transport_params_t *params)
{
    if (conn->tlsref.flags & XQC_CONN_FLAG_RECV_RETRY) {
        /* need finish recv retry packet
        if (!params->original_connection_id_present) {
            return -XQC_TLS_TRANSPORT_PARAM;
        }
        if (!xqc_cid_eq(&conn->rcid, &params->original_connection_id)) {
            return -XQC_TLS_TRANSPORT_PARAM;
        }
        */
    }

    return XQC_OK;
}


static xqc_int_t 
xqc_conn_set_remote_transport_params(xqc_connection_t *conn, 
    uint8_t exttype, const xqc_transport_params_t *params)
{
    xqc_int_t rv;

    switch (exttype) {

    case XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
        if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        break;

    case XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            return -XQC_TLS_INVALID_ARGUMENT;
        }
        rv = xqc_conn_client_validate_transport_params(conn, params);
        if (rv != 0) {
            return rv;
        }
        break;

    default:
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    xqc_settings_copy_from_transport_params(&conn->remote_settings, params);

    conn->tlsref.flags |= XQC_CONN_FLAG_TRANSPORT_PARAM_RECVED;

    return XQC_OK;
}


/* dst should be destination value point */
#define XQC_DECODE_VINT_VALUE(dst, p, end) \
    do { \
        ssize_t nread = xqc_vint_read((p), (end), (dst)); \
        if (nread < 0) { \
            return -XQC_TLS_MALFORMED_TRANSPORT_PARAM; \
        } \
        return XQC_OK; \
    } while(0) 


static xqc_int_t
xqc_decode_original_dest_cid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    xqc_cid_init(&params->original_dest_connection_id, p, param_len);
    params->original_dest_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_idle_timeout(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_idle_timeout, p, end);
}

static xqc_int_t
xqc_decode_stateless_token(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    if ((size_t)(end - p) < sizeof(params->stateless_reset_token) || 
        param_len != sizeof(params->stateless_reset_token))
    {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(params->stateless_reset_token, p, param_len);
    params->stateless_reset_token_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_udp_payload_size(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_udp_payload_size, p, end);
}

static xqc_int_t
xqc_decode_initial_max_data(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_data, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_bidi_local(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_bidi_local, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_bidi_remote(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_bidi_remote, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_uni(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_uni, p, end);
}

static xqc_int_t
xqc_decode_initial_max_streams_bidi(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_streams_bidi, p, end);
}

static xqc_int_t
xqc_decode_initial_max_streams_uni(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_streams_uni, p, end);
}

static xqc_int_t
xqc_decode_ack_delay_exponent(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    ssize_t nread = xqc_vint_read(p, end, &params->ack_delay_exponent);
    /* [TRANSPORT] Values above 20 are invalid */
    if (nread < 0 || params->ack_delay_exponent > 20) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_ack_delay(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_ack_delay, p, end);
}

static xqc_int_t
xqc_decode_disable_active_migration(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    /* disable_active_migration param is a zero-length value, if present, set to true */
    params->disable_active_migration = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_preferred_address(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                       const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    if ((end - p) < param_len) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    /* IPv4 addr */
    if ((end - p) < XQC_PREFERRED_ADDR_IPV4_LEN + XQC_PREFERRED_ADDR_IPV4_PORT_LEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(&params->preferred_address.ipv4, p, sizeof(params->preferred_address.ipv4));
    p += sizeof(params->preferred_address.ipv4);

    /* IPv4 port */
    params->preferred_address.ipv4_port = xqc_get_uint16(p);
    p += sizeof(uint16_t);

    /* IPv6 addr */
    if ((end - p) < XQC_PREFERRED_ADDR_IPV6_LEN + XQC_PREFERRED_ADDR_IPV6_PORT_LEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(&params->preferred_address.ipv6, p, sizeof(params->preferred_address.ipv6));
    p += sizeof(params->preferred_address.ipv6);

    /* IPv6 port */
    params->preferred_address.ipv6_port = xqc_get_uint16(p);
    p += sizeof(uint16_t);

    /* cid len */
    if ((end - p) < 1) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    params->preferred_address.cid.cid_len = *p++;
    if (params->preferred_address.cid.cid_len > XQC_MAX_CID_LEN
        || 0 == params->preferred_address.cid.cid_len   /* [Transport] 18.2 cid with zero-length MUST be treated as TRANSPORT_PARAMETER_ERROR */
        || (end - p) < params->preferred_address.cid.cid_len)
    {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    /* cid */
    if (params->preferred_address.cid.cid_len) {
        memcpy(params->preferred_address.cid.cid_buf, p,
                params->preferred_address.cid.cid_len);
        p += params->preferred_address.cid.cid_len;
    }

    /* stateless reset token */
    if ((end - p) < XQC_STATELESS_RESET_TOKENLEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }    
    memcpy(params->preferred_address.stateless_reset_token, p,
            sizeof(params->preferred_address.stateless_reset_token));
    p += sizeof(params->preferred_address.stateless_reset_token);

    params->preferred_address_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_active_cid_limit(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                                const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->active_connection_id_limit, p, end);
}

static xqc_int_t
xqc_decode_initial_scid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                            const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    xqc_cid_init(&params->initial_source_connection_id, p, param_len);
    params->initial_source_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_retry_scid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                          const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    xqc_cid_init(&params->retry_source_connection_id, p, param_len);
    params->retry_source_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_no_crypto(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
                          const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->no_crypto, p, end);
}

static xqc_int_t
xqc_decode_enable_multipath(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->enable_multipath, p, end);
}


/* decode value from p, and store value in the input params */
typedef xqc_int_t (*xqc_trans_param_decode_func)(
    xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len);

xqc_trans_param_decode_func xqc_trans_param_decode_func_list[] = {
    xqc_decode_original_dest_cid, 
    xqc_decode_max_idle_timeout, 
    xqc_decode_stateless_token,
    xqc_decode_max_udp_payload_size,
    xqc_decode_initial_max_data,
    xqc_decode_initial_max_stream_data_bidi_local,
    xqc_decode_initial_max_stream_data_bidi_remote,
    xqc_decode_initial_max_stream_data_uni,
    xqc_decode_initial_max_streams_bidi,
    xqc_decode_initial_max_streams_uni,
    xqc_decode_ack_delay_exponent,
    xqc_decode_max_ack_delay,
    xqc_decode_disable_active_migration,
    xqc_decode_preferred_address,
    xqc_decode_active_cid_limit,
    xqc_decode_initial_scid,
    xqc_decode_retry_scid,
    xqc_decode_no_crypto,
    xqc_decode_enable_multipath
};

/* convert param_type to param's index in dpvf_list */
xqc_int_t
xqc_trans_param_get_index(uint64_t param_type) 
{
    /**
     *  param in space below is illegal:
     * [XQC_TRANSPORT_PARAM_PROTOCOL_MAX, XQC_TRANSPORT_PARAM_NO_CRYPTO)
     * [XQC_TRANSPORT_PARAM_CUSTOMIZED_MAX, +infinite)
     */

    if (param_type < XQC_TRANSPORT_PARAM_PROTOCOL_MAX) {
        return param_type;
    } else if (param_type >= XQC_TRANSPORT_PARAM_NO_CRYPTO 
               && param_type < XQC_TRANSPORT_PARAM_UNKNOWN)
    {
        /* TBD: need to change to formal IANA registration */
        if (param_type == XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH) {
            return XQC_TRANSPORT_PARAM_PROTOCOL_MAX + 1;
        }
            
        return XQC_TRANSPORT_PARAM_PROTOCOL_MAX + param_type - XQC_TRANSPORT_PARAM_NO_CRYPTO;
    }

    return XQC_TRANSPORT_PARAM_UNKNOWN; 
}

static inline xqc_int_t
xqc_check_transport_params(xqc_transport_params_t *params)
{
    if (params->initial_max_streams_bidi > XQC_MAX_STREAMS
        || params->initial_max_streams_uni > XQC_MAX_STREAMS
        || params->initial_max_stream_data_bidi_local > XQC_MAX_STREAMS
        || params->initial_max_stream_data_bidi_remote > XQC_MAX_STREAMS
        || params->initial_max_stream_data_uni > XQC_MAX_STREAMS)
    {
        return -XQC_TLS_TRANSPORT_PARAM;
    }

    return XQC_OK;
}
/**
 * decode one param
 */
static inline xqc_int_t
xqc_trans_param_decode_one(xqc_connection_t *conn, 
    xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t **start, const uint8_t *end)
{
    const uint8_t* p = *start;
    uint64_t param_type = 0;
    uint64_t param_len = 0;

    /* read param type */
    ssize_t nread = xqc_vint_read(p, end, &param_type);
    if (nread < 0) {
        xqc_log(conn->log, XQC_LOG_WARN, "|transport parameter: decode param type error");
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    p += nread;

    /* read param len */
    nread = xqc_vint_read(p, end, &param_len);
    if (nread < 0 || p + nread + param_len > end ) {
        xqc_log(conn->log, XQC_LOG_WARN, "|transport parameter: decode param[%"PRIu64"] length error|nread:%"PRId64"|", param_type, nread);
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    p += nread;

    /* read param value, note: some parameters are allowed to be zero-length, for example, disable_active_migration */
    xqc_int_t param_index = xqc_trans_param_get_index(param_type);
    if (param_index != XQC_TRANSPORT_PARAM_UNKNOWN) {
        xqc_int_t ret = xqc_trans_param_decode_func_list[param_index](params, exttype, p, end, param_type, param_len);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|transport parameter: decode param[%"PRIu64"] value error|ret: %d|", param_type, ret);
            return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
        }

    } else {
        xqc_log(conn->log, XQC_LOG_WARN, "|transport parameter: unknown type|%"PRIu64"|", param_type);
    }
    p += param_len;

    *start = p;
    return XQC_OK;
}

static xqc_int_t
xqc_trans_param_decode(xqc_connection_t *conn,
    xqc_transport_params_t *params, xqc_transport_params_type_t exttype, 
    const uint8_t *data, size_t datalen)
{
    const uint8_t *p, *end;
    xqc_int_t ret = XQC_OK;

    p = data;
    end = data + datalen;

    /* Set default values */
    params->preferred_address_present = 0;
    params->original_dest_connection_id_present = 0;
    params->max_idle_timeout = 0;

    params->stateless_reset_token_present = 0;
    params->max_udp_payload_size = XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE;

    params->initial_max_data = 0;
    params->initial_max_streams_bidi = 0;
    params->initial_max_streams_uni = 0;
    params->initial_max_stream_data_bidi_local = 0;
    params->initial_max_stream_data_bidi_remote = 0;
    params->initial_max_stream_data_uni = 0;

    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    params->disable_active_migration = 1;  /* default disable */
    params->active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

    params->initial_source_connection_id_present = 0;
    params->initial_source_connection_id.cid_len = 0;
    params->retry_source_connection_id_present = 0;
    params->retry_source_connection_id.cid_len = 0;

    params->no_crypto = 0;

    while (p < end) {
        ret = xqc_trans_param_decode_one(conn, params, exttype, &p, end);
        if (ret < 0) {
            return ret;
        }
    }
    
    if (end != p) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    return xqc_check_transport_params(params);
}


static xqc_int_t 
xqc_write_transport_params(xqc_connection_t * conn,
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
    if (tp_data_len < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|write tp data error|ret code:%d|", tp_data_len);
        return -XQC_ESYS;
    }

    if (conn->tlsref.save_tp_cb != NULL) {
        conn->tlsref.save_tp_cb(tp_buf, tp_data_len, xqc_conn_get_user_data(conn));
    }

    return XQC_OK;
}


// public functions declared in header file

xqc_int_t
xqc_read_transport_params(char * tp_data, size_t tp_data_len, xqc_transport_params_t *params)
{
    if (strlen(tp_data) != tp_data_len) {
        tp_data[tp_data_len] = '\0';
    }

    char * p = tp_data;
    while (*p != '\0') {
        if ( *p == ' ') {
            p++;
        }

        if (strncmp(p, "initial_max_streams_bidi=", strlen("initial_max_streams_bidi=")) == 0) {
            p = p + strlen("initial_max_streams_bidi=");
            params->initial_max_streams_bidi = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_streams_uni=", strlen("initial_max_streams_uni=")) == 0) {
            p = p + strlen("initial_max_streams_uni=");
            params->initial_max_streams_uni = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_bidi_local=",
                           strlen("initial_max_stream_data_bidi_local=")) == 0)
        {
            p = p + strlen("initial_max_stream_data_bidi_local=");
            params->initial_max_stream_data_bidi_local = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_bidi_remote=",
                           strlen("initial_max_stream_data_bidi_remote=")) == 0)
        {
            p = p + strlen("initial_max_stream_data_bidi_remote=");
            params->initial_max_stream_data_bidi_remote = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_uni=", strlen("initial_max_stream_data_uni=")) == 0) {
            p = p + strlen("initial_max_stream_data_uni=");
            params->initial_max_stream_data_uni = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_data=", strlen("initial_max_data=")) == 0) {
            p = p + strlen("initial_max_data=");
            params->initial_max_data = strtoul(p, NULL, 10);

        } else if (strncmp(p, "max_ack_delay=", strlen("max_ack_delay=")) == 0) {
            p = p + strlen("max_ack_delay=");
            params->max_ack_delay = strtoul(p, NULL, 10);
        }

        p = strchr(p, '\n');
        if (p == NULL) {
            return 0;
        }
        p++;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_set_early_remote_transport_params(
    xqc_connection_t *conn, const xqc_transport_params_t *params)
{
    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        return -XQC_TLS_INVALID_STATE;
    }

    xqc_settings_copy_from_transport_params(&conn->remote_settings, params);

    return XQC_OK;
}

#define XQC_TRANSPORT_PARAM_BUF_LEN (512)
xqc_int_t 
xqc_serialize_client_transport_params(xqc_connection_t * conn,
    xqc_transport_params_type_t exttype, const unsigned char **out, size_t *outlen)
{
    xqc_transport_params_t params;
    memset(&params, 0, sizeof(xqc_transport_params_t));

    /* initialize params */
    xqc_int_t rv = xqc_conn_get_local_transport_params(conn, &params, exttype);
    if (rv != XQC_OK) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    uint8_t * buf = xqc_malloc(XQC_TRANSPORT_PARAM_BUF_LEN);
    if (buf == NULL) {
        return -XQC_TLS_NOBUF;
    }

    ssize_t nwrite = xqc_encode_transport_params(buf, XQC_TRANSPORT_PARAM_BUF_LEN, 
                                                 exttype, &params);
    if (nwrite < 0) {
        xqc_free((void*)(buf));
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    *out        = buf ;
    *outlen     = nwrite ;

    return XQC_OK;
}

xqc_int_t 
xqc_serialize_server_transport_params(xqc_connection_t * conn, xqc_transport_params_type_t exttype,const unsigned char **out,size_t *outlen)
{
    xqc_transport_params_t params;

    /* initialize params */
    xqc_int_t rv = xqc_conn_get_local_transport_params(
                conn, &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
    if (rv != XQC_OK) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    uint8_t *buf = xqc_malloc(XQC_TRANSPORT_PARAM_BUF_LEN);
    if (buf == NULL) {
        return -XQC_TLS_NOBUF;
    }

    ssize_t nwrite = xqc_encode_transport_params(buf, XQC_TRANSPORT_PARAM_BUF_LEN, 
        XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (nwrite < 0) {
        xqc_free((void*)buf);
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    *out    = buf;
    *outlen = nwrite;

    return XQC_OK;
}

#undef XQC_TRANSPORT_PARAM_BUF_LEN 


xqc_int_t 
xqc_on_client_recv_peer_transport_params(xqc_connection_t * conn,
    const unsigned char *inbuf,size_t inlen)
{
    xqc_transport_params_t params;

    xqc_int_t rv = xqc_trans_param_decode(conn,
                &params, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, inbuf, inlen);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_trans_param_decode failed| ret code:%d |", rv);
        return rv;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_set_remote_transport_params failed | ret code:%d |", rv);
        return rv;
    }

    if (conn->tlsref.save_tp_cb != NULL) {
        if (xqc_write_transport_params(conn, &params) < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_transport_params failed|");
            return rv;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_on_server_recv_peer_transport_params(xqc_connection_t * conn,
    const unsigned char *inbuf, size_t inlen)
{
    int rv;
    xqc_transport_params_t params;

    rv = xqc_trans_param_decode(conn, 
            &params, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, inbuf, inlen);
    if (rv != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_trans_param_decode| ret code :%d |", rv);
        return rv;
    }

    rv = xqc_conn_set_remote_transport_params(
            conn, XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (rv != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_set_remote_transport_params| ret code :%d|", rv);
        return rv;
    }

    /* save no crypto flag */
    if(params.no_crypto == 1){
        conn->remote_settings.no_crypto = 1;
        conn->local_settings.no_crypto = 1;
    }
    return XQC_OK;
}


