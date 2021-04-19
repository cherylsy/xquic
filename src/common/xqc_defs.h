#ifndef XQC_DEFS_H
#define XQC_DEFS_H

#include <stdint.h>

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

extern uint32_t xqc_proto_version_value[];
extern const unsigned char xqc_proto_version_field[][XQC_PROTO_VERSION_LEN];


#define xqc_check_proto_version_valid(ver) \
        ((ver) >= XQC_VERSION_V1 && (ver) < XQC_IDRAFT_VER_NEGOTIATION)


/**
 * xquic tls definitions
 */
extern const char* xqc_crypto_initial_salt[];


#endif