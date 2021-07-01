#ifndef XQC_TRANSPORT_PARAMS_H_
#define XQC_TRANSPORT_PARAMS_H_

#include <xquic/xquic.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_conn.h"

/**
 * transport paramter type
 */
typedef enum {
    /* transport parameter for client */
    XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,

    /* transport parameter for server */
    XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS

} xqc_transport_params_type_t;



typedef enum {
    XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID = 0x0000,
    XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT = 0x0001,
    XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
    XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE = 0x0003,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
    XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
    XQC_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
    XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION = 0x000c,
    XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d,
    XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x000e,
    XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x000f,
    XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID = 0x0010,
    XQC_TRANSPORT_PARAM_PROTOCOL_MAX,  /* upper limit of params defined in [Transport] */
    XQC_TRANSPORT_PARAM_NO_CRYPTO = 0x1000,
    XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH = 0xbaba,
    XQC_TRANSPORT_PARAM_UNKNOWN,  /* upper limit of params defined by xquic */
} xqc_transport_param_id_t;



/* For Handshake */
typedef struct {
    xqc_preferred_addr_t    preferred_address;
    uint8_t                 preferred_address_present;

    xqc_cid_t               original_dest_connection_id;
    uint8_t                 original_dest_connection_id_present;

    xqc_usec_t              max_idle_timeout;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 stateless_reset_token_present;
    uint64_t                max_udp_payload_size;
    uint64_t                initial_max_data;
    uint64_t                initial_max_stream_data_bidi_local;
    uint64_t                initial_max_stream_data_bidi_remote;
    uint64_t                initial_max_stream_data_uni;
    uint64_t                initial_max_streams_bidi;
    uint64_t                initial_max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_usec_t              max_ack_delay;
    xqc_flag_t              disable_active_migration;
    uint64_t                active_connection_id_limit;

    xqc_cid_t               initial_source_connection_id;
    uint8_t                 initial_source_connection_id_present;

    xqc_cid_t               retry_source_connection_id;
    uint8_t                 retry_source_connection_id_present;

    uint64_t                no_crypto;

    uint64_t                enable_multipath;
} xqc_transport_params_t;


/* default value for max_ack_delay */
#define XQC_DEFAULT_MAX_ACK_DELAY 25

/* default value for ack_delay_exponent */
#define XQC_DEFAULT_ACK_DELAY_EXPONENT 3

/* default value for max_udp_payload_size */
#define XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE 65527

/* default value for active_connection_id_limit */
#define XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT 2


/**
 * used to free buffers created by xqc_serialize_xxx_transport_parames functions
 */
static inline 
void xqc_transport_parames_serialization_free(void *buf) {
    if (buf) {
        xqc_free(buf);
    }
}

/**
 * set transport parameters from previous connection to xqc_connection_t
 * @param conn xquic connection handler
 * @param params transport parameters
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_conn_set_early_remote_transport_params(
    xqc_connection_t *conn, const xqc_transport_params_t *params);

/**
 * read transport parameters from buffer, which was stored during previous connection
 * @param tp_data transport parameters buffer, with xquic's pattern
 * @param tp_data_len transport parameters buffer length
 * @param params output transport parameter structure
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_read_transport_params(char *tp_data, size_t tp_data_len, xqc_transport_params_t *params);

/**
 * serialize client transport parameters. 
 * @param conn xquic connection handler
 * @param exttype the occasion of transport paramter
 * @param out pointer of destination buffer, to be freed with xqc_transport_parames_serialization_free
 * @param outlen serialized buffer len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_serialize_client_transport_params(xqc_connection_t *conn,
    xqc_transport_params_type_t exttype, const unsigned char **out, size_t *outlen);

/**
 * used by client to decode transport params from server
 * @param conn xquic connection handler
 * @param inbuf encoded transport parameter buf
 * @param inlen encoded transport parameter buf len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_on_client_recv_peer_transport_params(xqc_connection_t *conn,
    const unsigned char *inbuf, size_t inlen);

/**
 * serialize server's transport parameters
 * @param conn xquic connection handler
 * @param exttype the occurrence of transport parameter
 * @param out pointer of destination buffer, 
 * to be freed with xqc_transport_parames_serialization_free
 * @param outlen serialized buffer len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_serialize_server_transport_params(xqc_connection_t *conn,
    xqc_transport_params_type_t exttype, const unsigned char **out, size_t *outlen);

/**
 * used by server to docode transport params from client
 * @param conn xquic connection handler
 * @param inbuf encoded transport parameter buf
 * @param inlen encoded transport parameter buf len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_on_server_recv_peer_transport_params(xqc_connection_t *conn,
    const unsigned char *inbuf, size_t inlen);

#endif /* XQC_TRANSPORT_PARAMS_H_ */