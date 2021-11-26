#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/aead.h>
#include <openssl/evp.h>

#ifndef XQC_CRYPTO_PRIVAYE
#error "Do not include this file directly，include xqc_crypto.h"
#endif


/* Cipher id definition for tls 13 */
#define XQC_TLS13_AES_128_GCM_SHA256                TLS1_CK_AES_128_GCM_SHA256
#define XQC_TLS13_AES_256_GCM_SHA384                TLS1_CK_AES_256_GCM_SHA384
#define XQC_TLS13_CHACHA20_POLY1305_SHA256          TLS1_CK_CHACHA20_POLY1305_SHA256


#define XQC_CIPHER_SUITES_IMPL const EVP_CIPHER *
#define XQC_AEAD_SUITES_IMPL   const EVP_AEAD *

#define XQC_AEAD_OVERHEAD_IMPL(obj,cln)           (0) + (obj)->taglen


#define DO_NOT_CALL_XQC_AEAD_INIT(obj,a)        ({                           \
    obj->aead           = a;                                                 \
    obj->taglen         = EVP_AEAD_max_tag_len(obj->aead);                   \
    obj->keylen         = EVP_AEAD_key_length(obj->aead);                    \
    obj->noncelen       = EVP_AEAD_nonce_length(obj->aead);                  \
    obj->xqc_aead_encrypt_func = xqc_bssl_aead_encrypt;                      \
    obj->xqc_aead_decrypt_func = xqc_bssl_aead_decrypt;                      \
    0;})

#define DO_NOT_CALL_XQC_CIPHER_INIT(obj,c)        ({                         \
    obj->cipher         = c;                                                 \
    obj->keylen         = EVP_CIPHER_key_length(obj->cipher);                \
    obj->noncelen       = EVP_CIPHER_iv_length(obj->cipher);                 \
    0;})

#define XQC_AEAD_INIT_AES_GCM_IMPL(obj,d,...)   ({                           \
    xqc_packet_prot_aead_t * ___aead    = (obj);                             \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_aead_aes_##d##_gcm());             \
    0;})

#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj,...) ({                     \
    xqc_packet_prot_aead_t * ___aead = (obj);                                \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_aead_chacha20_poly1305());         \
    0;})

#define XQC_CIPHER_INIT_AES_CTR_IMPL(obj,d,...) ({                           \
    xqc_header_prot_cipher_t * ___cipher = (obj);                            \
    DO_NOT_CALL_XQC_CIPHER_INIT(___cipher,EVP_aes_##d##_ctr());              \
    ___cipher->xqc_hp_mask_func = xqc_bssl_hp_mask;                          \
    0;})

/* chacha20 follow openssl impl */
#define XQC_CIPHER_INIT_CHACHA20_IMPL(obj,...)  ({                           \
    xqc_header_prot_cipher_t * ___cipher = (obj);                            \
    ___cipher->keylen   = 32 ;                                               \
    ___cipher->noncelen = 16;                                                \
    ___cipher->xqc_hp_mask_func = xqc_bssl_hp_mask_chacha20;                 \
    0;})


/* extern */

xqc_int_t xqc_bssl_aead_encrypt(const xqc_packet_prot_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

xqc_int_t xqc_bssl_aead_decrypt(const xqc_packet_prot_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);


xqc_int_t xqc_bssl_hp_mask(const xqc_header_prot_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen);

xqc_int_t xqc_bssl_hp_mask_chacha20(const xqc_header_prot_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen);

#endif //XQC_AEAD_IMPL_H_