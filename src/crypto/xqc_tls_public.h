#ifndef _XQC_TLS_PUBLIC_H_INCLUDED_
#define _XQC_TLS_PUBLIC_H_INCLUDED_

#include <openssl/ssl.h>
#include <assert.h>
#include <ctype.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/common/xqc_str.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_malloc.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_defs.h"


#ifdef WORDS_BIGENDIAN
#  define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#  define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */

#define MAX_VALINT_VALUE 4611686018427387904ULL

#define XQC_TLSEXT_QUIC_TRANSPORT_PARAMETERS 0xffa5u

#define MAX_HOST_LEN 256

#define XQC_TRUE 1
#define XQC_FALSE 0

#define XQC_SSL_SUCCESS   1  /* openssl or boringssl 1 success */
#define XQC_SSL_FAIL      0  /* openssl or boringssl 0 failure */

#define XQC_SERVER 1
#define XQC_CLIENT 0


#define XQC_TLS_EARLY_DATA_ACCEPT (1)
#define XQC_TLS_EARLY_DATA_REJECT (-1)
#define XQC_TLS_NO_EARLY_DATA   (0)
#define XQC_TLS_EARLY_DATA_UNKNOWN (-2)  //early data status can read only after handshake completed

#define XQC_NONCE_LEN   16
#define XQC_UINT32_MAX  (0xffffffff)

/* Short header specific macros */
#define XQC_SHORT_KEY_PHASE_BIT 0x04

/* XQC_STATELESS_RESET_TOKENLEN is the length of Stateless Reset
 *    Token. */
#define XQC_STATELESS_RESET_TOKENLEN 16

#define XQC_MAX_PKT_NUM ((1llu << 62) - 1)

#ifndef xqc_min
#define xqc_min(A, B) ((A) < (B) ? (A) : (B))
#endif

#define XQC_PKT_NUMLEN_MASK 0x03

#define XQC_HP_SAMPLELEN 16
#define XQC_HP_MASKLEN 5

#define INITIAL_SECRET_MAX_LEN  32

#define XQC_INITIAL_AEAD_OVERHEAD XQC_TLS_AEAD_OVERHEAD_MAX_LEN


typedef enum {
    XQC_ALPN_DEFAULT_NUM = 0,
    XQC_ALPN_HTTP3_NUM = 1,
    XQC_ALPN_TRANSPORT_NUM = 2,
}xqc_alpn_num;

typedef enum {
  //XQC_CONN_FLAG_NONE = 0x00,
  /* XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX is set if handshake
     completed. */
  XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX = 0x01,
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
  /*XQC_CONN_FLAG_RETRY_SENT means server already send retry packet */
  XQC_CONN_FLAG_RETRY_SENT = 0x1000,
}xqc_conn_flag;


#define XQC_MAX_SERVER_ID_BIDI 0x3fffffffffffff00ULL
#define XQC_MAX_SERVER_ID_UNI 0x3fffffffffffff10ULL
#define XQC_MAX_CLIENT_ID_BIDI 0x3fffffffffffff01ULL
#define XQC_MAX_CLIENT_ID_UNI 0x3fffffffffffff11ULL


#define XQC_256_K  (256*1024)
#define XQC_1_M (1024*1024)

#define XQC_CONN_TIMEOUT 30


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



typedef struct {
    xqc_client_initial client_initial;
    xqc_recv_client_initial recv_client_initial;
    xqc_recv_crypto_data recv_crypto_data;
    xqc_handshake_completed handshake_completed;
    xqc_recv_version_negotiation recv_version_negotiation;
    /**
     * in_encrypt is a callback function which is invoked to encrypt
     * Initial packets.
     */
    xqc_encrypt_t in_encrypt;
    /**
     * in_decrypt is a callback function which is invoked to decrypt
     * Initial packets.
     */
    xqc_decrypt_t in_decrypt;
    /**
     * encrypt is a callback function which is invoked to encrypt
     * packets other than Initial packets.
     */
    xqc_encrypt_t encrypt;
    /**
     * decrypt is a callback function which is invoked to decrypt
     * packets other than Initial packets.
     */
    xqc_decrypt_t decrypt;
    /**
     * in_hp_mask is a callback function which is invoked to get mask to
     * encrypt or decrypt Initial packet header.
     */
    xqc_hp_mask_t in_hp_mask;
    /**
     * hp_mask is a callback function which is invoked to get mask to
     * encrypt or decrypt packet header other than Initial packets.
     */
    xqc_hp_mask_t hp_mask;

    xqc_update_key_t update_key;

    xqc_recv_retry recv_retry;
} xqc_tls_callbacks_t;

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


typedef enum {
    XQC_CRYPTO_KM_FLAG_NONE,
    /* XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE is set if key phase bit is
     *      set. */
    XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE = 0x01,
} xqc_crypto_km_flag;

/*@struct
 * every packet number space has its own key,iv and hpkey,
 * */
typedef struct {
    /* last_tx_pkt_num is the packet number which the local endpoint
     sent last time.*/
    uint64_t last_tx_pkt_num;

    xqc_crypto_km_t  rx_ckm;
    xqc_crypto_km_t  tx_ckm;
    xqc_vec_t  rx_hp;  //header protect key
    xqc_vec_t  tx_hp;

    xqc_list_head_t  msg_cb_head;
    xqc_list_head_t  msg_cb_buffer;
}xqc_pktns_t;

//for temporary
#define MAX_HS_BUFFER (2*1024)
struct xqc_hs_buffer{
    xqc_list_head_t list_head;
    //uint16_t read_n;
    size_t data_len;
    char data[];
};
typedef struct xqc_hs_buffer xqc_hs_buffer_t;


static inline xqc_hs_buffer_t * xqc_create_hs_buffer(int buf_size){

    xqc_hs_buffer_t * p_buf = xqc_malloc(sizeof(xqc_hs_buffer_t) + buf_size);
    if(p_buf == NULL)return NULL;
    xqc_init_list_head(&p_buf->list_head);
    p_buf->data_len = buf_size;
    return p_buf;
}


//just temporary, need rewrite with frame structure
typedef struct {
  xqc_list_head_t buffer_list;
  uint8_t type;
  uint16_t data_len;
  char data[XQC_MAX_PACKET_LEN];
}xqc_data_buffer_t;

//callback function
typedef int  (*xqc_read_session_cb_t )(char ** data);

typedef int (*xqc_early_data_cb_t)(xqc_connection_t *conn, int flag); // 1 means early data accept, 0 means early data reject

struct xqc_tlsref
{
    xqc_connection_t        *conn;
    uint8_t                 initial;
    uint8_t                 resumption;
    xqc_alpn_num            alpn_num;
    uint64_t                flags; //record handshake completed or recv retry packet
   
#define hs_crypto_ctx crypto_ctx_store[XQC_ENC_LEV_INIT] 
#define crypto_ctx    crypto_ctx_store[XQC_ENC_LEV_0RTT]
    xqc_tls_context_t       crypto_ctx_store[XQC_ENC_MAX_LEVEL] ;

    xqc_pktns_t             initial_pktns; // initial packet space key
    xqc_pktns_t             hs_pktns; // handshake packet space  key
    xqc_pktns_t             pktns; //application packet space key

    xqc_crypto_km_t         early_ckm;
    xqc_vec_t               early_hp;

    xqc_crypto_km_t        new_tx_ckm;
    xqc_crypto_km_t        new_rx_ckm;
    xqc_crypto_km_t        old_rx_ckm;

    xqc_vec_t              tx_secret;
    xqc_vec_t              rx_secret;

    xqc_hs_buffer_t        * hs_to_tls_buf;

    xqc_conn_ssl_config_t  conn_ssl_config;

    xqc_tls_callbacks_t    callbacks;

    xqc_save_session_pt     save_session_cb;
    xqc_save_trans_param_pt save_tp_cb;
    xqc_cert_verify_pt      cert_verify_cb;
    uint8_t                 cert_verify_flag;

    void *                  tp_user_data;
    void *                  session_user_data;

    xqc_early_data_cb_t    early_data_cb;

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
  //assert(n < 4611686018427387904ULL);
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
  //assert(n < 4611686018427387904ULL);
  if(n >= 4611686018427387904ULL){
    return NULL;
  }
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
  rv = inet_pton(family, hostname, dst); // ip transfer success return 1, else return 0 or -1
  return rv == 1;
}

// if host is number ,return 1, else return 0
static inline int xqc_numeric_host(const char *hostname) {
  return xqc_check_numeric_host(hostname, AF_INET) || xqc_check_numeric_host(hostname, AF_INET6);
}


static inline size_t xqc_get_varint_len(const uint8_t *p) { return 1u << (*p >> 6); }
static inline int64_t xqc_get_varint_fb(const uint8_t *p) { return *p & 0x3f; }

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

    return 0; //impossible
}

static inline ssize_t xqc_decode_varint(uint64_t *pdest, const uint8_t *p,
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
    if(vec->base)xqc_free(vec->base);
    vec->base = NULL;
    vec->len = 0;
}

static inline int xqc_vec_assign(xqc_vec_t * vec, const uint8_t * data, size_t data_len){
    vec->base = xqc_malloc(data_len);
    if(vec->base == NULL){
        return -1;
    }
    memcpy(vec->base, data, data_len);
    vec->len = data_len;
    return 0;
}

static inline void xqc_vec_move(xqc_vec_t *dest_vec, xqc_vec_t * src_vec){
    dest_vec->base = src_vec->base;
    src_vec->base = NULL;
    dest_vec->len = src_vec->len;
    src_vec->len = 0;
}


#ifdef XQC_PRINT_SECRET
void xqc_tls_print_secret(SSL *ssl, xqc_connection_t *conn, enum ssl_encryption_level_t level,
    const unsigned char *read_secret, const unsigned char *write_secret, size_t secretlen);
#endif



#endif
