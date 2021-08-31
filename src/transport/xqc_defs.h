#ifndef XQC_DEFS_H
#define XQC_DEFS_H

#include <stdint.h>
#include <xquic/xquic.h>

#define XQC_MAX_PACKET_LEN 1500

/* default connection timeout(millisecond) */
#define XQC_CONN_DEFAULT_IDLE_TIMEOUT 120000

#define XQC_CONN_ADDR_VALIDATION_CID_ENTROPY    8

/* connection PTO packet count */
#define XQC_CONN_PTO_PKT_CNT_MAX    2

/* connection max UDP payload size */
#define XQC_CONN_MAX_UDP_PAYLOAD_SIZE   1500

/* connection active cid limit */
#define XQC_CONN_ACTIVE_CID_LIMIT       8


#define XQC_VERSION_V1_VALUE        0x00000001
#define XQC_IDRAFT_VER_29_VALUE     0xFF00001D
#define XQC_IDRAFT_VER_33_VALUE     0xFF000021

#define XQC_PROTO_VERSION_LEN 4

extern const uint32_t xqc_proto_version_value[];
extern const unsigned char xqc_proto_version_field[][XQC_PROTO_VERSION_LEN];


#define xqc_check_proto_version_valid(ver) \
        ((ver) > XQC_IDRAFT_INIT_VER && (ver) < XQC_IDRAFT_VER_NEGOTIATION)


/**
 * Initial salt for handshake
 */
extern const char* const xqc_crypto_initial_salt[];

/**
 * ALPN definitions
 */
#define XQC_ALPN_H3         "h3"
#define XQC_ALPN_H3_29      "h3-29"

#define XQC_ALPN_TRANSPORT  "transport"

#define XQC_ALPN_LIST "\x2h3\x5h3-29\x9transport"

xqc_bool_t
xqc_alpn_type_is_h3(const unsigned char *alpn, uint8_t alpn_len);

xqc_bool_t
xqc_alpn_type_is_transport(const unsigned char *alpn, uint8_t alpn_len);

extern const char* const xqc_h3_alpn[];


#endif