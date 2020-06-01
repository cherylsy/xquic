#ifndef XQC_CRYPTO_H_
#define XQC_CRYPTO_H_

#include <stdio.h>
#include <stdint.h>
#include <xquic/xquic.h>
#include "src/crypto/xqc_aead.h"

#define XQC_FAKE_AEAD_OVERHEAD XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

struct xqc_aead_st
{
    // aead ctx 
    const void * ctx ;

    // quick query
    size_t taglen   ;
    size_t keylen   ;
    size_t noncelen ;
};

struct xqc_crypto_st 
{
    // aead ctx 
    const void * aead_ctx ;

    size_t taglen   ;
    size_t keylen   ;
    size_t noncelen ;

    struct 
    {
        // for user define ctx 。 normaly set ctx = aead_ctx ;
        const void * encrypt_ctx ;
        ssize_t 
        (*xqc_encrypt_func) (uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen) ;
    }encrypt;

    struct 
    {
        // normaly set ctx = aead_ctx 
        const void * decrypt_ctx ;
        ssize_t 
        (*xqc_decrypt_func) (uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen, const xqc_crypto_t *ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen) ;
    }decrypt;
};

struct xqc_crypto_hp_st 
{
    // aead ctx 
    const void * aead_ctx ;
    
    size_t taglen   ;
    size_t keylen   ;
    size_t noncelen ;
    
    struct 
    {
        // weird 
        ssize_t 
        (*xqc_hp_mask_func)(uint8_t *dest, size_t destlen, const xqc_crypto_hp_t *ctx,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen);
    }hp_mask;
};

ssize_t 
xqc_null_cipher_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen);

ssize_t 
xqc_null_cipher_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen);

ssize_t 
xqc_null_cipher_hp_mask (uint8_t *dest, size_t destlen, const xqc_crypto_hp_t *ctx,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen);


// Return ZERO on success ,init plaintext always success 
#define xqc_crypto_init_plaintext(obj,d)    ({                                                  \
    xqc_aead_t * ___aead = (xqc_aead_t *)(obj);                                                 \
    ___aead->keylen = ___aead->noncelen = 1 ;                                                   \
    ___aead->taglen = (d);                                                                      \
    _Generic((obj),                                                                             \
        xqc_crypto_t * : ({                                                                     \
            xqc_crypto_t * ___crypto = (xqc_crypto_t*)(___aead) ;                               \
            ___crypto->encrypt.xqc_encrypt_func = xqc_null_cipher_encrypt ;                     \
            ___crypto->decrypt.xqc_decrypt_func = xqc_null_cipher_decrypt ;                     \
        }),                                                                                     \
        xqc_crypto_hp_t * : ({                                                             \
            xqc_crypto_hp_t * ___crypto_hp_mask = (xqc_crypto_hp_t*) (___aead);       \
            ___crypto_hp_mask->hp_mask.xqc_hp_mask_func = xqc_null_cipher_hp_mask ;             \
        })                                                                                      \
    );                                                                                          \
    0;                                                                                          \
})

// Return ZERO on success ;
#define xqc_crypto_init(obj,aead_init,...)  ({                                                  \
    xqc_aead_t * ___aead = (xqc_aead_t *)(obj);                                                 \
    aead_init(___aead,__VA_ARGS__);                                                             \
    _Generic((obj),                                                                             \
        xqc_crypto_t * : ({                                                                     \
            xqc_crypto_t * ___crypto = (xqc_crypto_t*)(___aead) ;                               \
            XQC_INIT_CRYPTO(___crypto);                                                         \
        }),                                                                                     \
        xqc_crypto_hp_t * : ({                                                                  \
            xqc_crypto_hp_t * ___crypto_hp_mask = (xqc_crypto_hp_t*) (___aead);                 \
            XQC_INIT_CRYPTO_HP_MASK(___crypto_hp_mask);                                         \
        })                                                                                      \
    );                                                                                          \
    0;})

static inline 
ssize_t 
xqc_crypto_encrypt(const xqc_crypto_t * crypto,uint8_t *dest, size_t destlen, 
            const uint8_t *plaintext,size_t plaintextlen, 
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    }
    else {
        return crypto->encrypt.xqc_encrypt_func(dest,destlen,
                plaintext,plaintextlen,
                crypto,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }
}

static inline 
ssize_t 
xqc_crypto_decrypt(const xqc_crypto_t * crypto,uint8_t *dest, size_t destlen, 
            const uint8_t *ciphertext,size_t ciphertextlen, 
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    }
    else {
        return crypto->decrypt.xqc_decrypt_func(dest,destlen,
                ciphertext,ciphertextlen,
                crypto,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }
}

static inline
ssize_t 
xqc_crypto_hp_mask(const xqc_crypto_hp_t * hp_mask,
            uint8_t *dest, size_t destlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    if(XQC_UNLIKELY(hp_mask == NULL)) {
        return -1 ;
    }
    else {
        return hp_mask->hp_mask.xqc_hp_mask_func(dest,destlen,hp_mask,key,keylen,sample,samplelen);
    }
}

#endif // XQC_CRYPTO_H_