#ifndef _XQC_TLS_PUBLIC_H_INCLUDED_
#define _XQC_TLS_PUBLIC_H_INCLUDED_

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <assert.h>
#include "xqc_crypto.h"
#include "include/xquic_typedef.h"
#include "common/xqc_str.h"

#ifdef WORDS_BIGENDIAN
#  define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#  define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */


#define XQC_TLSEXT_QUIC_TRANSPORT_PARAMETERS 0xffa5u
#define XQC_MAX_PKT_SIZE  65527 //quic protocol define

/*XQC_DEFAULT_ACK_DELAY_EXPONENT is a default value of scaling
 *factor of ACK Delay field in ACK frame.
 */
#define XQC_DEFAULT_ACK_DELAY_EXPONENT 3

/**
 * @macro
 *
 * XQC_DEFAULT_MAX_ACK_DELAY is a default value of the maximum
 * amount of time in milliseconds by which endpoint delays sending
 * acknowledgement.
 */
#define XQC_DEFAULT_MAX_ACK_DELAY 25

/* Short header specific macros */
#define XQC_SHORT_SPIN_BIT_MASK 0x20
#define XQC_SHORT_RESERVED_BIT_MASK 0x18
#define XQC_SHORT_KEY_PHASE_BIT 0x04

/* XQC_STATELESS_RESET_TOKENLEN is the length of Stateless Reset
 *    Token. */
#define XQC_STATELESS_RESET_TOKENLEN 16

#ifndef xqc_min
#define xqc_min(A, B) ((A) < (B) ? (A) : (B))
#endif

typedef enum {
  //XQC_CONN_FLAG_NONE = 0x00,
  /* XQC_CONN_FLAG_HANDSHAKE_COMPLETED is set if handshake
     completed. */
  //XQC_CONN_FLAG_HANDSHAKE_COMPLETED = 0x01,
  /* XQC_CONN_FLAG_CONN_ID_NEGOTIATED is set if connection ID is
     negotiated.  This is only used for client. */
  XQC_CONN_FLAG_CONN_ID_NEGOTIATED = 0x02,
  /* XQC_CONN_FLAG_TRANSPORT_PARAM_RECVED is set if transport
     parameters are received. */
  XQC_CONN_FLAG_TRANSPORT_PARAM_RECVED = 0x04,
  /* XQC_CONN_FLAG_RECV_PROTECTED_PKT is set when a protected
     packet is received, and decrypted successfully.  This flag is
     used to stop retransmitting handshake packets.  It might be
     replaced with an another mechanism when we implement key
     update. */
  XQC_CONN_FLAG_RECV_PROTECTED_PKT = 0x08,
  /* XQC_CONN_FLAG_RECV_RETRY is set when a client receives Retry
     packet. */
  XQC_CONN_FLAG_RECV_RETRY = 0x10,
  /* XQC_CONN_FLAG_EARLY_DATA_REJECTED is set when 0-RTT packet is
     rejected by a peer. */
  XQC_CONN_FLAG_EARLY_DATA_REJECTED = 0x20,
  /* XQC_CONN_FLAG_SADDR_VERIFIED is set when source address is
     verified. */
  XQC_CONN_FLAG_SADDR_VERIFIED = 0x40,
  /* XQC_CONN_FLAG_OCID_PRESENT is set when ocid field of
     xqc_conn is set. */
  XQC_CONN_FLAG_OCID_PRESENT = 0x80,
  /* XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED is set when the
     library transitions its state to "post handshake". */
  XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED = 0x0100,
  /* XQC_CONN_FLAG_FORCE_SEND_INITIAL is set when client has to
     send Initial packets even if it has nothing to send. */
  XQC_CONN_FLAG_FORCE_SEND_INITIAL = 0x0200,
  /* XQC_CONN_FLAG_INITIAL_KEY_DISCARDED is set when Initial keys
     have been discarded. */
  XQC_CONN_FLAG_INITIAL_KEY_DISCARDED = 0x0400,
  /* XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE is set when local
     endpoint has initiated key update and waits for the remote
     endpoint to update key. */
  XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE = 0x0800,
}xqc_conn_flag;


#define XQC_MAX_SERVER_ID_BIDI 0x3fffffffffffff00ULL
#define XQC_MAX_SERVER_ID_UNI 0x3fffffffffffff10ULL
#define XQC_MAX_CLIENT_ID_BIDI 0x3fffffffffffff01ULL
#define XQC_MAX_CLIENT_ID_UNI 0x3fffffffffffff11ULL


typedef enum {
    XQC_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID = 0x0000,
    XQC_TRANSPORT_PARAM_IDLE_TIMEOUT = 0x0001,
    XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
    XQC_TRANSPORT_PARAM_MAX_PACKET_SIZE = 0x0003,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
    XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
    XQC_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
    XQC_TRANSPORT_PARAM_DISABLE_MIGRATION = 0x000c,
    XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d,
} xqc_transport_param_id;


typedef enum {
    XQC_IP_VERSION_NONE = 0,
    XQC_IP_VERSION_4 = 4,
    XQC_IP_VERSION_6 = 6
} xqc_ip_version;

typedef enum {
    XQC_PKT_FLAG_NONE = 0,
    XQC_PKT_FLAG_LONG_FORM = 0x01,
    XQC_PKT_FLAG_KEY_PHASE = 0x04
} xqc_pkt_flag;


/*@struct address
 * */
typedef struct {
    xqc_cid_t cid;
    /* ip_addresslen is the length of ip_address. */
    size_t ip_addresslen;
    uint16_t port;
    /* ip_version is the version of IP address.  It should be one of the
     * defined values in :type:`xqc_ip_version`.
     *:enum:`XQC_IP_VERSION_NONE` indicates that no preferred
     *address is set and the other fields are ignored. */
    uint8_t ip_version;
    uint8_t ip_address[255];
    uint8_t stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_preferred_addr_t;

typedef struct {
    union {
        struct {
            uint32_t initial_version;
        } ch;
        struct {
            uint32_t negotiated_version;
            uint32_t supported_versions[63];
            size_t len;
        } ee;
    } v;
    xqc_preferred_addr_t preferred_address;
    xqc_cid_t original_connection_id;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_data;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t idle_timeout;
    uint64_t max_packet_size;
    uint8_t stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t stateless_reset_token_present;
    uint64_t ack_delay_exponent;
    uint8_t disable_migration;
    uint8_t original_connection_id_present;
    uint64_t max_ack_delay;
} xqc_transport_params_t;

typedef enum {
    XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
    XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS
} xqc_transport_params_type_t;



typedef struct {
    xqc_preferred_addr_t preferred_address;
    //xqc_tstamp initial_ts;
    uint64_t max_stream_data_bidi_local;
    uint64_t max_stream_data_bidi_remote;
    uint64_t max_stream_data_uni;
    uint64_t max_data;
    uint64_t max_streams_bidi;
    uint64_t max_streams_uni;
    uint64_t idle_timeout;
    uint64_t max_packet_size;
    uint8_t stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t stateless_reset_token_present;
    uint64_t ack_delay_exponent;
    uint8_t disable_migration;
    uint64_t max_ack_delay;
} xqc_settings_t;


struct xqc_ssl_config {
    char       *private_key_file;
    char       *cert_file;
    const char *ciphers;
    const char *groups;
};
typedef struct xqc_ssl_config xqc_ssl_config_t;


/**
 * @struct
 * xqc_vec is struct iovec compatible structure to reference
 * arbitrary array of bytes.
 */
typedef struct {
  /* base points to the data. */
  uint8_t *base;
  /* len is the number of bytes which the buffer pointed by base
     contains. */
  size_t len;
} xqc_vec_t;

typedef struct {
    xqc_vec_t key;
    xqc_vec_t iv;
    /* pkt_num is a packet number of a packet which uses this keying
     * material.  For encryption key, it is the lowest packet number of
     * a packet.  For decryption key, it is the lowest packet number of
     * a packet which can be decrypted with this keying material. */
    uint64_t pkt_num;
    /* flags is the bitwise OR of zero or more of
     *      _crypto_km_flag. */
    uint8_t flags;
} xqc_crypto_km_t;


/*@struct
 * every packet number space has its own key,iv and hpkey,
 * */
typedef struct {
    /* crypto_rx_offset_base is the offset of crypto stream in the
     global TLS stream and it specifies the offset where this local
     crypto stream starts. */
    uint64_t crypto_rx_offset_base;

    xqc_crypto_km_t  rx_ckm;
    xqc_crypto_km_t  tx_ckm;
    xqc_vec_t  rx_hp;  //header protect key
    xqc_vec_t  tx_hp;
}xqc_pktns_t;


struct xqc_tlsref{
    int server;
    unsigned int flags;
    uint64_t max_local_stream_id_bidi;
    uint64_t max_local_stream_id_uni;
    xqc_settings_t local_settings;
    xqc_settings_t remote_settings;

    uint32_t aead_overhead;  //aead for gcm or chacha

    xqc_tls_context_t          crypto_ctx; /* prf and aead */
    xqc_tls_context_t          hs_crypto_ctx;
    xqc_pktns_t            initial_pktns; // initial packet space key
    xqc_pktns_t            hs_pktns; // handshake packet space  key
    xqc_pktns_t            pktns; //application packet space key

    xqc_crypto_km_t        early_ckm;
    xqc_vec_t              early_hp;

};
typedef struct xqc_tlsref xqc_tlsref_t;


static inline uint16_t xqc_get_uint16(const uint8_t *p) {
    uint16_t n;
    memcpy(&n, p, 2);
    return ntohs(n);
}


static inline uint32_t xqc_get_uint24(const uint8_t *p) {
    uint32_t n = 0;
    memcpy(((uint8_t *)&n) + 1, p, 3);
    return ntohl(n);
}

static inline uint32_t xqc_get_uint32(const uint8_t *p) {
    uint32_t n;
    memcpy(&n, p, 4);
    return ntohl(n);
}


static inline void xqc_cid_init(xqc_cid_t *cid, const uint8_t *data, size_t datalen) {
    assert(datalen <= sizeof(cid->cid_buf));

    cid->cid_len = datalen;
    if (datalen) {
        memcpy(cid->cid_buf, data, datalen);
    }
}

/*define in common/xqc_str.h
static inline uint8_t * xqc_cpymem(uint8_t *dest, uint8_t * src, size_t n){
    memcpy(desc, src, n);
    return desc + n;
}*/

static inline size_t xqc_put_varint_len(uint64_t n) {
  if (n < 64) {
    return 1;
  }
  if (n < 16384) {
    return 2;
  }
  if (n < 1073741824) {
    return 4;
  }
  assert(n < 4611686018427387904ULL);
  return 8;
}




static inline uint8_t *xqc_put_uint64be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

static inline uint8_t *xqc_put_uint48be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return xqc_cpymem(p, ((const uint8_t *)&n) + 2, 6);
}

static inline uint8_t *xqc_put_uint32be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

static inline uint8_t *xqc_put_uint24be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return xqc_cpymem(p, ((const uint8_t *)&n) + 1, 3);
}

static inline uint8_t *xqc_put_uint16be(uint8_t *p, uint16_t n) {
  n = htons(n);
  return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}


static inline uint8_t *xqc_put_varint(uint8_t *p, uint64_t n) {
  uint8_t *rv;
  if (n < 64) {
    *p++ = (uint8_t)n;
    return p;
  }
  if (n < 16384) {
    rv = xqc_put_uint16be(p, (uint16_t)n);
    *p |= 0x40;
    return rv;
  }
  if (n < 1073741824) {
    rv = xqc_put_uint32be(p, (uint32_t)n);
    *p |= 0x80;
    return rv;
  }
  assert(n < 4611686018427387904ULL);
  rv = xqc_put_uint64be(p, n);
  *p |= 0xc0;
  return rv;
}

static inline int xqc_cid_eq(const xqc_cid_t *cid, const xqc_cid_t *other) {
    return cid->cid_len == other->cid_len &&
        0 == memcmp(cid->cid_buf, other->cid_buf, cid->cid_len);
}


static inline uint64_t xqc_nth_server_bidi_id(uint64_t n) {
    if (n == 0) {
        return 0;
    }
    return ((n - 1) << 2) | 0x01;
}
static inline uint64_t xqc_nth_client_bidi_id(uint64_t n) {
    if (n == 0) {
        return 0;
    }
    return (n - 1) << 2;
}

static inline uint64_t xqc_nth_server_uni_id(uint64_t n) {
    if (n == 0) {
        return 0;
    }

    return ((n - 1) << 2) | 0x03;
}

static inline uint64_t xqc_nth_client_uni_id(uint64_t n) {
    if (n == 0) {
        return 0;
    }

    return ((n - 1) << 2) | 0x02;
}



static inline int xqc_check_numeric_host(const char *hostname, int family) {
  int rv;
  uint8_t dst[32];
  rv = inet_pton(family, hostname, dst);
  return rv == 1;
}

// if host is number ,return 1, else return 0
static inline int xqc_numeric_host(const char *hostname) {
  return xqc_check_numeric_host(hostname, AF_INET) || xqc_check_numeric_host(hostname, AF_INET6);
}


static inline size_t xqc_get_varint_len(const uint8_t *p) { return 1u << (*p >> 6); }

static inline uint64_t xqc_get_varint(size_t *plen, const uint8_t *p) {
    union {
        char b[8];
        uint16_t n16;
        uint32_t n32;
        uint64_t n64;
    } n;

    *plen = xqc_get_varint_len(p);

    switch (*plen) {
        case 1:
            return *p;
        case 2:
            memcpy(&n, p, 2);
            n.b[0] &= 0x3f;
            return ntohs(n.n16);
        case 4:
            memcpy(&n, p, 4);
            n.b[0] &= 0x3f;
            return ntohl(n.n32);
        case 8:
            memcpy(&n, p, 8);
            n.b[0] &= 0x3f;
            return bswap64(n.n64);
    }

    assert(0);
}

static inline size_t xqc_decode_varint(uint64_t *pdest, const uint8_t *p,
        const uint8_t *end) {
    uint16_t len = xqc_get_uint16(p);
    size_t n;

    p += sizeof(uint16_t);

    switch (len) {
        case 1:
        case 2:
        case 4:
        case 8:
            break;
        default:
            return -1;
    }

    if ((size_t)(end - p) < len) {
        return -1;
    }

    n = xqc_get_varint_len(p);
    if (n != len) {
        return -1;
    }

    *pdest = xqc_get_varint(&n, p);

    return (size_t)(sizeof(uint16_t) + len);
}


static inline void xqc_vec_init(xqc_vec_t * vec){
    vec->base = NULL;
    vec->len = 0;
}

static inline void xqc_vec_free(xqc_vec_t *vec) {
    free(vec->base);
    vec->base = NULL;
    vec->len = 0;
}



#endif
