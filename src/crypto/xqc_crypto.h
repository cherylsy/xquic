#ifndef XQC_CRYPTO_H_
#define XQC_CRYPTO_H_


#include <stdio.h>
#include <stdint.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>

typedef struct xqc_aead_st          xqc_aead_t ;
typedef struct xqc_crypto_st        xqc_crypto_t ;

#undef  XQC_CRYPTO_PRIVAYE
#define XQC_CRYPTO_PRIVAYE

#ifdef OPENSSL_IS_BORINGSSL
#include "src/crypto/boringssl/xqc_aead_impl.h"
#else 
#include "src/crypto/openssl/xqc_aead_impl.h"
#endif 

#undef  XQC_CRYPTO_PRIVAYE

#define XQC_FAKE_AEAD_OVERHEAD XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

// check if crypto_obj has been initiated 
#define xqc_crypto_is_init(obj)           ((obj->encrypt.xqc_encrypt_func))

// crypto 和 aead 共有 noncelen 和 keylen 字段。 
#define xqc_crypto_key_length(obj)      ((obj)->keylen)
#define xqc_crypto_iv_length(obj)       ((obj)->noncelen)


// tag长度,一般我们不会对crypto求taglen，因为是没有意义的。这里的0后续可以修改为 XQC_UN_REACHABLE
#define xqc_aead_taglen(obj)         (obj)->taglen

// 这里我们暂时只需要如下几种加密算法的实现
// 所有的初始化都需要完整的填充所有数据。

#ifdef XQC_AEAD_INIT_NULL_IMPL
#define xqc_aead_init_null(aead,tgl,...)            XQC_AEAD_INIT_NULL_IMPL(aead,tgl,__VA_ARGS__)
#else // XQC_AEAD_INIT_NULL_IMPL
xqc_int_t xqc_aead_init_null(xqc_aead_t * aead,size_t taglen) ;
#endif // XQC_AEAD_INIT_NULL_IMPL

// aes_d_gcm  d 即密钥长度
#define xqc_aead_init_aes_gcm(aead,d,...)           XQC_AEAD_INIT_AES_GCM_IMPL(aead,d,__VA_ARGS__)

// chacha20_poly1305
#define xqc_aead_init_chacha20_poly1305(obj,...)    XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj,__VA_ARGS__)


#ifdef XQC_CRYPTO_INIT_NULL_IMPL
#define xqc_crypto_init_null(crypto,...)            XQC_CRYPTO_INIT_NULL_IMPL(crypto,__VA_ARGS__)
#else   // XQC_CRYPTO_INIT_NULL_IMPL
xqc_int_t xqc_crypto_init_null(xqc_crypto_t * crypto);
#endif // XQC_CRYPTO_INIT_NULL_IMPL

// aes_d_ctr 
#define xqc_crypto_init_aes_ctr(crypto,d,...)       XQC_CRYPTO_INIT_AES_CTR_IMPL(crypto,d,__VA_ARGS__)

// chacha20
#define xqc_crypto_init_chacha20(crypto,...)        XQC_CRYPTO_INIT_CHACHA20_IMPL(crypto,__VA_ARGS__)

// private ，不推荐直接调用。
#define xqc_cipher_overhead(obj,cln)                XQC_CIPHER_OVERHEAD_IMPL((obj),cln)
#define xqc_aead_overhead(obj,cln)                  (XQC_AEAD_OVERHEAD_IMPL((obj),cln))

// crypto单指不做认证的加密
#define XQC_CRYPTO_CTX_TYPE     XQC_CRYPTO_CTX_TYPE_IMPL
// aead指需要做认证的加解密。 
#define XQC_AEAD_CTX_TYPE       XQC_AEAD_CTX_TYPE_IMPL

struct xqc_crypto_st 
{
    XQC_CRYPTO_CTX_TYPE ctx     ;
    size_t keylen;
    size_t noncelen;

    struct 
    {
        ssize_t 
        (*xqc_encrypt_func)(const xqc_crypto_t *ctx,uint8_t *dest, size_t destlen, 
            const uint8_t *plaintext,size_t plaintextlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen);
    }encrypt;
};

struct xqc_aead_st 
{
    XQC_AEAD_CTX_TYPE   ctx     ;
    size_t keylen               ;
    size_t noncelen             ;
    size_t taglen               ;     

    struct 
    {
        ssize_t 
        (*xqc_encrypt_func) ( const xqc_aead_t * ctx,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen,const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen) ;
    }encrypt;

    struct 
    {
        ssize_t 
        (*xqc_decrypt_func) (const xqc_aead_t *ctx,uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen,  const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen) ;
    }decrypt;
};


static inline 
ssize_t 
xqc_aead_encrypt(const xqc_aead_t * crypto,uint8_t *dest, size_t destlen, 
            const uint8_t *plaintext,size_t plaintextlen, 
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    }
    else {
        return crypto->encrypt.xqc_encrypt_func(
                crypto,dest,destlen,
                plaintext,plaintextlen,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }
}

static inline 
ssize_t 
xqc_aead_decrypt(const xqc_aead_t * crypto,uint8_t *dest, size_t destlen, 
            const uint8_t *ciphertext,size_t ciphertextlen, 
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    }
    else {
        return crypto->decrypt.xqc_decrypt_func(
                crypto,
                dest,destlen,
                ciphertext,ciphertextlen,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }
}


static inline ssize_t 
xqc_crypto_encrypt(const xqc_crypto_t * crypto,
    uint8_t *dest, size_t destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen, const uint8_t *sample,
    size_t samplelen)
{
    if(XQC_UNLIKELY(crypto == NULL)) {
        return -1 ;
    } else {
        return crypto->encrypt.xqc_encrypt_func(crypto,dest,destlen,plaintext,plaintextlen,key,keylen,sample,samplelen);
    }
}

#endif // XQC_CRYPTO_H_
