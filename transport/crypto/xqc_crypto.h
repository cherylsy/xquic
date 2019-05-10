#ifndef _XQC_CRYPTO_H_INCLUDED_
#define _XQC_CRYPTO_H_INCLUDED_

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "include/xquic_typedef.h"

#define XQC_PKT_NUMLEN_MASK 0x03

#define XQC_HP_SAMPLELEN 16
#define XQC_HP_MASKLEN 5

#define XQC_INITIAL_AEAD_OVERHEAD 16

/* XQC_INITIAL_SALT is a salt value which is used to derive initial
   secret. */
#define XQC_INITIAL_SALT                                                    \
  "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e"   \
  "\x09\xa0"

struct xqc_tls_context {
#if defined(OPENSSL_IS_BORINGSSL)
  const EVP_AEAD *aead;
#else  // !OPENSSL_IS_BORINGSSL
  const EVP_CIPHER *aead;
#endif // !OPENSSL_IS_BORINGSSL
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  //std::array<uint8_t, 64> tx_secret, rx_secret;
  //size_t secretlen;
};
typedef struct xqc_tls_context xqc_tls_context_t;


typedef struct {
  //xqc_cid_t dcid;
  //xqc_cid_t scid;
  uint64_t pkt_num;
  uint8_t *token;
  size_t tokenlen;
  /**
   * pkt_numlen is the number of bytes spent to encode pkt_num.
   */
  size_t pkt_numlen;
  /**
   * len is the sum of pkt_numlen and the length of QUIC packet
   * payload.
   */
  size_t len;
  uint32_t version;
  uint8_t type;
  uint8_t flags;
} xqc_pkt_hd;

int xqc_negotiated_prf(xqc_tls_context_t * ctx, SSL *ssl);
// negotiated_aead stores the negotiated AEAD by TLS into |ctx|.  This
// function returns 0 if it succeeds, or -1.

int xqc_negotiated_aead(xqc_tls_context_t *ctx, SSL *ssl);

int xqc_derive_initial_secret(uint8_t *dest, size_t destlen,
        const  xqc_cid_t *cid, const uint8_t *salt,
        size_t saltlen);

void xqc_aead_aes_128_gcm(xqc_tls_context_t *ctx) ;
int xqc_derive_client_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen);

size_t xqc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);

size_t xqc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);

size_t xqc_derive_header_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);

int xqc_conn_install_initial_tx_keys(xqc_connection_t *conn, uint8_t *key,
                                        size_t keylen, uint8_t *iv,
                                        size_t ivlen,  uint8_t *pn,
                                        size_t pnlen);

int xqc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen);


int xqc_conn_install_initial_rx_keys(xqc_connection_t *conn, uint8_t *key,
                                        size_t keylen,  uint8_t *iv,
                                        size_t ivlen, uint8_t *pn,
                                        size_t pnlen);

void xqc_prf_sha256(xqc_tls_context_t *ctx);


void xqc_conn_set_aead_overhead(xqc_connection_t *conn, size_t aead_overhead) ;

size_t xqc_aead_max_overhead(const xqc_tls_context_t *ctx);

int xqc_conn_install_early_keys(xqc_connection_t *conn, const uint8_t *key,
                                   size_t keylen, const uint8_t *iv,
                                   size_t ivlen, const uint8_t *pn,
                                   size_t pnlen);

int xqc_conn_install_handshake_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen);

int xqc_conn_install_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv, size_t ivlen,
        const uint8_t *pn, size_t pnlen);

int xqc_conn_install_handshake_tx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen);

int xqc_conn_install_tx_keys(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen,
                                const uint8_t *pn, size_t pnlen);


size_t xqc_no_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

size_t xqc_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

size_t xqc_no_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

size_t xqc_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

size_t xqc_no_hp_mask(uint8_t *dest, size_t destlen, const xqc_tls_context_t *ctx,
                const uint8_t *key, size_t keylen, const uint8_t *sample,
                size_t samplelen);

size_t xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_tls_context_t  *ctx,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen);


void xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen,
        uint64_t pkt_num) ;

#endif
