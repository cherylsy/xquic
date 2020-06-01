#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>


typedef struct xqc_aead_st          xqc_aead_t ;
typedef struct xqc_crypto_st        xqc_crypto_t ;
typedef struct xqc_crypto_hp_st     xqc_crypto_hp_t;


// 这里我们目前所使用到的全部都是没有额外的开销的（除tag之外）
#define XQC_AEAD_EXTRA_OVERHEAD_IMPL(obj,cln)            (0)
// 
#define XQC_AEAD_CTX_IMPL(obj)                   ((const EVP_CIPHER *) ((obj)->aead_ctx))

extern 
ssize_t xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_crypto_hp_t  *ctx,
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

// obj is (xqc_crypto_t *)
#define XQC_INIT_CRYPTO_IMPL(obj)               do {                \
    (obj)->encrypt.xqc_encrypt_func = xqc_encrypt;                  \
    (obj)->decrypt.xqc_decrypt_func = xqc_decrypt;                  \
}while(0)

// obj is (xqc_crypto_hp_mask_t*)
#define XQC_INIT_CRYPTO_HP_MASK_IMPL(obj)        do{  obj->hp_mask.xqc_hp_mask_func =  xqc_hp_mask;} while(0)


#define XQC_AEAD_COMMON_OP(obj,c,tgl)   do {                \
    const EVP_CIPHER    * ___cipher = c ;                   \
    xqc_crypto_t        * ___crypto = (xqc_crypto_t*)(obj); \
    ___crypto->aead_ctx             = ___cipher;            \
    ___crypto->taglen               = (tgl);                \
    ___crypto->keylen   = EVP_CIPHER_key_length(___cipher); \
    ___crypto->noncelen = EVP_CIPHER_iv_length(___cipher);  \
}while(0)


#define XQC_AEAD_INIT_AES_GCM_IMPL(obj,d)  ({                               \
    XQC_AEAD_COMMON_OP(obj,EVP_aes_##d##_gcm(),EVP_GCM_TLS_TAG_LEN);        \
    0;                                                                      \
})

#define XQC_AEAD_INIT_AES_CTR_IMPL(obj,d) ({                                \
    XQC_AEAD_COMMON_OP(obj,EVP_aes_##d##_ctr(),EVP_GCM_TLS_TAG_LEN);        \
    0;                                                                      \
})

#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj,...) ({                                \
    XQC_AEAD_COMMON_OP(obj,EVP_chacha20_poly1305(),EVP_CHACHAPOLY_TLS_TAG_LEN);         \
    0;                                                                                  \
})

#endif 