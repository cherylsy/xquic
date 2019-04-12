#ifndef _XQC_CRYPTO_H_INCLUDED_
#define _XQC_CRYPTO_H_INCLUDED_

#include <openssl/ssl.h>
#include <openssl/evp.h>
//#include <openssl/kdf.h>

#define XQC_HP_SAMPLELEN 16
#define XQC_HP_MASKLEN 5

struct xqc_tls_context {
#if defined(OPENSSL_IS_BORINGSSL)
  const EVP_AEAD *aead;
#else  // !OPENSSL_IS_BORINGSSL
  const EVP_CIPHER *aead;
#endif // !OPENSSL_IS_BORINGSSL
  //const EVP_CIPHER *hp;
  const EVP_MD *prf;
  //std::array<uint8_t, 64> tx_secret, rx_secret;
  //size_t secretlen;
};
typedef struct xqc_tls_context xqc_tls_context_t;


int xqc_negotiated_prf(xqc_tls_context_t * ctx, SSL *ssl);
// negotiated_aead stores the negotiated AEAD by TLS into |ctx|.  This
// function returns 0 if it succeeds, or -1.

int xqc_negotiated_aead(xqc_tls_context_t *ctx, SSL *ssl);

#endif
