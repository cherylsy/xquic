#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifndef XQC_CRYPTO_PRIVAYE
#error "Do not include this file directly，include xqc_crypto.h"
#endif

#define XQC_CRYPTO_SUITES_IMPL        const EVP_CIPHER  *
 
#define XQC_AEAD_SUITES_IMPL          XQC_CRYPTO_SUITES_IMPL 

#define XQC_CRYPTO_CTX                EVP_CIPHER_CTX *

#define XQC_AEAD_CTX                  XQC_CRYPTO_CTX

// no overhead for cipher 
#define  XQC_CIPHER_OVERHEAD_IMPL(obj,cln)         (0)
// overhead for aead 
#define  XQC_AEAD_OVERHEAD_IMPL(obj,cln)           (0) + (obj)->taglen

// do not call directly !!!
#define DO_NOT_CALL_XQC_OPENSSL_CRYPTO_COMMON_INIT(obj,cipher)    ({    \
    obj->ctx        = cipher ;                                          \
    obj->keylen     = EVP_CIPHER_key_length(obj->ctx);                  \
    obj->noncelen   = EVP_CIPHER_iv_length(obj->ctx);                   \
})

// do not call directly !!!
#define DO_NOT_CALL_XQC_AEAD_INIT(obj,cipher,tgl)    ({                 \
    DO_NOT_CALL_XQC_OPENSSL_CRYPTO_COMMON_INIT(obj,cipher);             \
    obj->taglen = (tgl);                                                \
    obj->aead_crypter_builder     = &openssl_aead_crypter_builder ;     \
    obj->encrypt.xqc_encrypt_func = xqc_ossl_aead_encrypt;              \
    obj->decrypt.xqc_decrypt_func = xqc_ossl_aead_decrypt;              \
})

// do not call directly !!!
#define DO_NOT_CALL_XQC_CRYPTO_INIT(obj,cipher)     ({                  \
    DO_NOT_CALL_XQC_OPENSSL_CRYPTO_COMMON_INIT(obj,cipher);             \
    obj->crypter_builder    =  &openssl_crypter_builder ;               \
    obj->encrypt.xqc_encrypt_func = xqc_ossl_crypto_encrypt;            \
})

#define XQC_AEAD_INIT_AES_GCM_IMPL(obj,d,...)   ({                                  \
    xqc_aead_t * ___aead  = (obj);                                                  \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_aes_##d##_gcm(),EVP_GCM_TLS_TAG_LEN);     \
})

#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj,...) ({                                        \
    xqc_aead_t * ___aead = (obj);                                                               \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_chacha20_poly1305(),EVP_CHACHAPOLY_TLS_TAG_LEN);      \
})

#define XQC_CRYPTO_INIT_AES_CTR_IMPL(obj,d,...) ({                      \
    xqc_crypto_t * ___crypto = (obj);                                   \
    DO_NOT_CALL_XQC_CRYPTO_INIT(___crypto,EVP_aes_##d##_ctr());         \
})

#define XQC_CRYPTO_INIT_CHACHA20_IMPL(obj,...)  ({                      \
    xqc_crypto_t * ___crypto = (obj);                                   \
    DO_NOT_CALL_XQC_CRYPTO_INIT(___crypto,EVP_chacha20());              \
})

/*** extern encrtpt */

ssize_t 
xqc_ossl_aead_decrypt(const xqc_aead_t *ctx, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen,const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

ssize_t 
xqc_ossl_aead_encrypt(const xqc_aead_t *ctx,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen,  const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) ;

ssize_t
xqc_ossl_crypto_encrypt(const xqc_crypto_t*ctx,uint8_t *dest, size_t destlen, 
        const uint8_t *plaintext,size_t plaintextlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen);


extern xqc_crypter_builder_t        openssl_crypter_builder;
extern xqc_aead_crypter_builder_t   openssl_aead_crypter_builder;

#endif 