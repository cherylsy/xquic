/**
 * @copyright Copyright (c) 2021
 * @brief definitions for interfaces
 */
#ifndef XQC_TLS_DEFS_H
#define XQC_TLS_DEFS_H

#include <xquic/xquic.h>
#include "src/common/xqc_common_defs.h"
#include "src/common/xqc_common.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_common_inc.h"


#define XQC_TLS_AEAD_OVERHEAD_MAX_LEN   16


typedef struct xqc_tls_ctx_s xqc_tls_ctx_t;
typedef struct xqc_tls_s xqc_tls_t;


typedef enum {
    XQC_TLS_TYPE_SERVER = 0x00,
    XQC_TLS_TYPE_CLIENT,
} xqc_tls_type_t;


/**
 * @brief encryption levels, equivalent to the definition in ssl lib
 */
typedef enum xqc_encrypt_level_s {
    XQC_ENC_LEV_INIT,

    XQC_ENC_LEV_0RTT,

    XQC_ENC_LEV_HSK,

    XQC_ENC_LEV_1RTT,

    XQC_ENC_LEV_MAX,
} xqc_encrypt_level_t;


typedef enum {
    XQC_KEY_TYPE_RX_READ,
    XQC_KEY_TYPE_TX_WRITE,
} xqc_key_type_t;


/* definitions for early data accept */
typedef enum xqc_tls_early_data_accept_s {

    XQC_TLS_EARLY_DATA_UNKNOWN  = -2,

    XQC_TLS_EARLY_DATA_REJECT   = -1,

    XQC_TLS_NO_EARLY_DATA       = 0,

    XQC_TLS_EARLY_DATA_ACCEPT   = 1
} xqc_tls_early_data_accept_t;


/**
 * @brief transport paramter type
 */
typedef enum {
    /* transport parameter for client */
    XQC_TP_TYPE_CLIENT_HELLO,

    /* transport parameter for server */
    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS

} xqc_transport_params_type_t;


/**
 * @brief definition of transport parameter types
 */
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


typedef struct {
    uint8_t     ipv4[4];
    uint16_t    ipv4_port;
    uint8_t     ipv6[16];
    uint16_t    ipv6_port;
    xqc_cid_t   cid;
    uint8_t     stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_preferred_addr_t;


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


/**
 * @brief tls config for create xqc_tls_t instance
 */
typedef struct xqc_tls_config_s {
    // TODO: 全部改成unsigned char *
    /* session ticket, only for client */
    unsigned char          *session_ticket;
    size_t                  session_ticket_len;

    /* bit-map flag defined in xqc_cert_verify_flag_e, only for client */
    uint8_t                 cert_verify_flag;

    /* hostname of server, only for client */
    char                   *hostname;

    /* alpn string, only for client */
    char                   *alpn;

    /**
     * no_crypto flag, only for client.
     * 1 for processing 0-RTT/1-RTT packets without encryption or decryption
     */
    int                     no_crypto_flag;

    /* local transport parameter, REQUIRED for both client and server */
    xqc_transport_params_t  trans_params;


} xqc_tls_config_t;


/**
 * @brief crypto data callback. the data is generated when doing tls handshake, and upper layer
 * shall wrap it as CRYPTO frame.
 */
typedef xqc_int_t (*xqc_tls_crypto_data_pt)(xqc_encrypt_level_t level, const uint8_t *data,
    size_t len, void *user_data);
// TODO: 错误码返回与结果明确
typedef void (*xqc_tls_trans_param_pt)(const xqc_transport_params_t *tp, void *user_data);

typedef xqc_int_t (*xqc_tls_alpn_select_pt)(const char *alpn, size_t alpn_len, void *user_data);

typedef xqc_int_t (*xqc_tls_cert_pt)(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *user_data);

typedef void (*xqc_tls_session_pt)(const char *data, size_t data_len, void *user_data);

typedef xqc_keylog_pt xqc_tls_keylog_pt;

/**
 * @brief tls fatal error callback. which will be triggered when ssl reported an tls error.
 * the parameter tls_err is from tls. which ranges in [0, 255], upper layer shall convert it to QUIC
 * CONNECTION_CLOSE error codes (CRYPTO_ERROR, 0x0100-0x01ff).
 */
typedef void (*xqc_tls_error_pt)(xqc_int_t tls_err, void *user_data);   // TODO: check细tls_err的范围，明确下错误码是否必须CLOSE

typedef void (*xqc_tls_handshake_completed)(void *user_data);

/**
 * @brief definition of callback functions to upper layer
 */
typedef struct xqc_tls_callbacks_s {

    /* generated crypto data callback function */
    xqc_tls_crypto_data_pt          crypto_data_cb;

    /* transport parameter callback function */
    xqc_tls_trans_param_pt          tp_cb;

    /* alpn selection callback function */
    xqc_tls_alpn_select_pt          alpn_select_cb;

    /* certificate verify callback function */
    xqc_tls_cert_pt                 cert_verify_cb;

    /* session ticket callback function */
    xqc_tls_session_pt              session_cb;

    /* for writing tx and rx secrets */
    xqc_tls_keylog_pt               keylog_cb;

    /* for notify tls errors, upper layer shall translate it 
       to CRYPTO_ERROR and close connection */
    xqc_tls_error_pt                error_cb;

    /* for notify tls handshake completed, which is equivalent to QUIC handshake completed */
    xqc_tls_handshake_completed     hsk_completed_cb;
} xqc_tls_callbacks_t;



#endif
