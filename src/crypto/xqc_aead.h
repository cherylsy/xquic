#ifndef XQC_AEAD_H_
#define XQC_AEAD_H_

/**
 *  @author 不达 
 * */

#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>


#define XQC_FAKE_AEAD_OVERHEAD XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

typedef struct xqc_crypto xqc_crypto_t ;

struct xqc_crypto 
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

    struct 
    {
        // weird 
        ssize_t 
        (*xqc_hp_mask_func)(uint8_t *dest, size_t destlen, const xqc_crypto_t *ctx,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen);
    }hp_mask;

};


#ifdef OPENSSL_IS_BORINGSSL
#include "src/crypto/boringssl/xqc_aead_impl.h"
#else 
#include "src/crypto/openssl/xqc_aead_impl.h"
#endif 

// 初始化为空加密器，不同的库有不同的实现。因此这里直接屏蔽底层实现。
void xqc_crypto_init_plaintext(xqc_crypto_t * crypto,size_t taglen) ;
//初始化aex_xxx_gcm实现
#define xqc_crypto_init_aes_gcm(obj,d)                  XQC_CRYPTO_INIT_AES_GCM_IMPL(obj,d)
// 初始化aex_xxx_ctr实现
#define xqc_crypto_init_aes_ctr(obj,d)                  XQC_CRYPTO_INIT_AES_CTR_IMPL(obj,d)
// 初始化chacha20_poly1305实现
#define xqc_crypto_init_chacha_20_poly1305(obj)         XQC_CRYPTO_INIT_CHACHA_20_POLY1305_IMPL(obj)

// 获取加密算法额外产生的大小开销，特别的当obj==NULL时，总是应返回0 ；
#define xqc_aead_extra_overhead(obj,cln)                XQC_AEAD_EXTRA_OVERHEAD_IMPL(obj,cln)

// 获取算法参数
#define xqc_crypto_overhead(crypto,cln)     ((crypto)->taglen + xqc_aead_extra_overhead(crypto->aead_ctx,cln))
#define xqc_crypto_taglen(crypto)           ((crypto)->taglen)
#define xqc_crypto_keylen(crypto)           ((crypto)->keylen)
#define xqc_crypto_noncelen(crypto)         ((crypto)->noncelen)

#define xqc_crypto_aead_ctx(crypto)         XQC_CRYPTO_AEAD_CTX_IMPL(crypto)

// unused right now 
#define  xqc_cipher_suites_release(obj)      

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
xqc_crypto_hp_mask(const xqc_crypto_t * crypto,
            uint8_t *dest, size_t destlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    }
    else {
        return crypto->hp_mask.xqc_hp_mask_func(dest,destlen,crypto,key,keylen,sample,samplelen);
    }
}


#endif //XQC_AEAD_H_