#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>


// 这里我们目前所使用到的全部都是没有额外的开销的（除tag之外）
#define XQC_AEAD_EXTRA_OVERHEAD_IMPL(obj,cln)            (0)
// 
#define XQC_CRYPTO_AEAD_CTX_IMPL(obj)                   ((const EVP_CIPHER *) ((obj)->aead_ctx))

extern 
ssize_t xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_crypto_t  *ctx,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen);

extern
ssize_t xqc_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_crypto_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);
extern 
ssize_t 
xqc_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, const xqc_crypto_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) ;


#define XQC_CRYPTO_COMMON_OP(obj,c,tgl)   do {              \
    const EVP_CIPHER    * ___cipher = c ;                   \
    xqc_crypto_t        * ___crypto = (obj);                \
    ___crypto->aead_ctx             = ___cipher;            \
    ___crypto->taglen               = (tgl);                \
    ___crypto->keylen   = EVP_CIPHER_key_length(___cipher); \
    ___crypto->noncelen = EVP_CIPHER_iv_length(___cipher);  \
    ___crypto->encrypt.xqc_encrypt_func    = xqc_encrypt ;  \
    ___crypto->decrypt.xqc_decrypt_func    = xqc_decrypt ;  \
    ___crypto->hp_mask.xqc_hp_mask_func    = xqc_hp_mask ;  \
}while(0)


#define XQC_CRYPTO_INIT_AES_GCM_IMPL(obj,d)  ({                             \
    XQC_CRYPTO_COMMON_OP(obj,EVP_aes_##d##_gcm(),EVP_GCM_TLS_TAG_LEN);      \
    0;                                                                      \
})

#define XQC_CRYPTO_INIT_AES_CTR_IMPL(obj,d) ({                              \
    XQC_CRYPTO_COMMON_OP(obj,EVP_aes_##d##_ctr(),EVP_GCM_TLS_TAG_LEN);      \
    0;                                                                      \
})

#define XQC_CRYPTO_INIT_CHACHA_20_POLY1305_IMPL(obj) ({                                 \
    XQC_CRYPTO_COMMON_OP(obj,EVP_chacha20_poly1305(),EVP_CHACHAPOLY_TLS_TAG_LEN);       \
    0;                                                                                  \
})

#endif 