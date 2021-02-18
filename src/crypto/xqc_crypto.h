#ifndef XQC_CRYPTO_H_
#define XQC_CRYPTO_H_


#include <stdio.h>
#include <stdint.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>

typedef struct xqc_aead_st          xqc_aead_t ;
typedef struct xqc_crypto_st        xqc_crypto_t ;

typedef struct xqc_crypter_builder_st         xqc_crypter_builder_t;
typedef struct xqc_aead_crypter_builder_st    xqc_aead_crypter_builder_t;

typedef struct xqc_crypter_st       xqc_crypter_t ;
typedef struct xqc_aead_crypter_st  xqc_aead_crypter_t;

#undef  XQC_CRYPTO_PRIVAYE
#define XQC_CRYPTO_PRIVAYE

#ifdef OPENSSL_IS_BORINGSSL
#include "src/crypto/boringssl/xqc_aead_impl.h"
#else 
#include "src/crypto/openssl/xqc_aead_impl.h"
#endif 

#undef  XQC_CRYPTO_PRIVAYE

#ifndef XQC_AEAD_CTX
#define XQC_AEAD_CTX void *
#endif 

#ifndef XQC_CRYPTO_CTX
#define XQC_CRYPTO_CTX void *
#endif 

typedef XQC_AEAD_CTX    xqc_aead_ctx_t ;
typedef XQC_CRYPTO_CTX  xqc_crypto_ctx_t ;

#define XQC_FAKE_AEAD_OVERHEAD XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

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
#define XQC_CRYPTO_SUITES     XQC_CRYPTO_SUITES_IMPL
// aead指需要做认证的加解密。 
#define XQC_AEAD_SUITES       XQC_AEAD_SUITES_IMPL

struct xqc_crypter_builder_st {

    /**
    *   new crypter
    * */
    xqc_crypter_t * (*xqc_crypter_new) (const xqc_crypto_t *crypto,int enc);

    /**
    *  free encrypter 
    * */
    void (*xqc_crypter_free) (xqc_crypter_t *crypter);

    /**
    * set or update key 
    * */
    ssize_t (*xqc_crypter_set_key) (xqc_crypter_t *crypter,const unsigned char *key,size_t keylen);

    /**
     * set or update nonce 
     * */
    ssize_t (*xqc_crypter_set_nonce)(xqc_crypter_t *crypter,const uint8_t *sample,size_t samplelen);

    /**
     * feed data 
     * */
    ssize_t (*xqc_crypter_update) (xqc_crypter_t *crypter,uint8_t *dest, size_t destlen,
        const uint8_t *source, size_t sourcelen);

    /**
    *  final 
    * */
    ssize_t (*xqc_crypter_final) (xqc_crypter_t *crypter,uint8_t *dest, size_t destlen);

};  

struct xqc_aead_crypter_builder_st
{
    /**
    *   new crypter
    *   enc 1 : encrpter 
    *   enc 0 : decrypter
    * */
    xqc_aead_crypter_t * (*xqc_aead_crypter_new) (const xqc_aead_t *aead,int enc);

    /**
    *  free aead encrypter 
    * */
    void (*xqc_aead_crypter_free) (xqc_aead_crypter_t *crypter);

    /**
    * set or update key 
    * */
    ssize_t (*xqc_aead_crypter_set_key) (xqc_aead_crypter_t *crypter,const unsigned char *key,size_t keylen);

#define xqc_aead_crypter_seal xqc_aead_crypter_operation
#define xqc_aead_crypter_open xqc_aead_crypter_operation
    /**
     *  for 
     * */
    ssize_t (*xqc_aead_crypter_operation) (xqc_aead_crypter_t *crypter,uint8_t *out, size_t max_out_len, 
        const uint8_t *nonce, size_t nonce_len, 
        const uint8_t *in, size_t in_len,
        const uint8_t *ad, size_t ad_len);

};

struct xqc_crypter_st 
{
    int enc;
    xqc_crypto_ctx_t ctx ;
    const xqc_crypto_t *crypto;
};

struct xqc_aead_crypter_st 
{
    int enc;
    xqc_aead_ctx_t ctx ;
    const xqc_aead_t *aead;
};

struct xqc_crypto_st 
{
    size_t keylen;
    size_t noncelen;
    XQC_CRYPTO_SUITES ctx;
    const xqc_crypter_builder_t *crypter_builder ;
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
    size_t keylen               ;
    size_t noncelen             ;
    XQC_AEAD_SUITES   ctx       ;
    size_t taglen               ;
    const xqc_aead_crypter_builder_t    *aead_crypter_builder ;
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

/**
 *  null cipher 
 * */
extern xqc_crypter_builder_t        xqc_null_crypter;
extern xqc_aead_crypter_builder_t   xqc_null_aead_crypter;


static inline 
xqc_crypter_t* xqc_crypter_new(const xqc_crypter_builder_t *builder,const xqc_crypto_t * crypto,int enc) {
    if (XQC_UNLIKELY(!builder || !builder->xqc_crypter_new)) {
        return NULL ;
    }
    return builder->xqc_crypter_new(crypto,!!enc);
}

static inline 
void xqc_crypter_free(const xqc_crypter_builder_t *builder,xqc_crypter_t* crypter) {
    if (XQC_UNLIKELY(!builder || !builder->xqc_crypter_free)) {
        return ;
    }
    builder->xqc_crypter_free(crypter);
}

static inline 
xqc_aead_crypter_t* xqc_aead_crypter_new(const xqc_aead_crypter_builder_t *builder,const xqc_aead_t * aead,int enc) {
    if (XQC_UNLIKELY(!builder || !builder->xqc_aead_crypter_new)) {
        return NULL ;
    }
    return builder->xqc_aead_crypter_new(aead,!!enc);
}

static inline 
void xqc_aead_crypter_free(const xqc_aead_crypter_builder_t *builder,xqc_aead_crypter_t* aead_crypter) {
    if (XQC_UNLIKELY(!builder || !builder->xqc_aead_crypter_free)) {
        return ;
    }
    builder->xqc_aead_crypter_free(aead_crypter);
}

#define xqc_crypter_call_impl(builder,prefix,op,...)   ({   \
    ssize_t __r = -1;                                       \
    if (builder && builder->prefix##_##op) {                \
        __r = builder->prefix##_##op(__VA_ARGS__);          \
    }                                                       \
    __r;                                                    \
})

#define xqc_crypter_call(builder,op,...)        xqc_crypter_call_impl(builder,xqc_crypter,op,__VA_ARGS__) 
#define xqc_aead_crypter_call(builder,op,...)   xqc_crypter_call_impl(builder,xqc_aead_crypter,op,__VA_ARGS__)

static inline 
ssize_t 
xqc_crypto_encrypt(const xqc_crypto_t * crypto,
    uint8_t *dest, size_t destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen, const uint8_t *sample,
    size_t samplelen, xqc_crypter_t * encrypter)
{
    int owns = 1;
    ssize_t len = -1 , out = -1 ;
    const xqc_crypter_builder_t *builder = crypto->crypter_builder ;

    if (encrypter){
        owns = 0 ;
        goto start ;
    }

    // some impl has no builder 
    if (builder == NULL) {
        return crypto->encrypt.xqc_encrypt_func(crypto,dest,destlen,
            plaintext,plaintextlen,
            key,keylen,
            sample,samplelen);
    }

    // new encrypter 
    encrypter = builder->xqc_crypter_new(crypto,/** enc */ 1) ;
    if (XQC_UNLIKELY(!encrypter)) {
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    // set key and nonce 
    (void) xqc_crypter_call(builder, set_key, encrypter, key, keylen);
start:
    (void) xqc_crypter_call(builder, set_nonce, encrypter, sample, samplelen);

    // update input 
    len = builder->xqc_crypter_update(encrypter, dest, destlen, plaintext, plaintextlen);
    if (len < 0 || XQC_UNLIKELY(len > destlen)) {
        out = -XQC_TLS_ENCRYPT_DATA_ERROR ;
        goto finish ;
    }

    // save 
    out = len ;

    // update offset 
    dest += len;
    destlen -= len ;

    // final , maybe padding  
    len = builder->xqc_crypter_final(encrypter, dest,destlen) ;
    if (len < 0 || XQC_UNLIKELY(len > destlen)) {
        out = -XQC_TLS_ENCRYPT_DATA_ERROR ;
        goto finish ;
    }
    
    out += len ;

finish:
    if (owns){
        builder->xqc_crypter_free(encrypter);
    }
    return out ;
}

static inline 
ssize_t 
xqc_aead_encrypt(const xqc_aead_t * aead,uint8_t *dest, size_t destlen, 
            const uint8_t *plaintext,size_t plaintextlen, 
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen,
            xqc_aead_crypter_t *aead_encrypter)
{
    int owns = 1;
    ssize_t outlen = -1, l ;
    const xqc_aead_crypter_builder_t *builder = aead->aead_crypter_builder ;

    if (aead_encrypter){
        owns = 0 ;
        goto start;
    }

    if (XQC_UNLIKELY(!builder)) {
        //TODO 
        return aead->encrypt.xqc_encrypt_func(
                aead,dest,destlen,
                plaintext,plaintextlen,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }

    // new encrypter
    aead_encrypter = builder->xqc_aead_crypter_new(aead,/** enc */ 1); 
    if (XQC_UNLIKELY(!aead_encrypter)) {
        return -XQC_TLS_ENCRYPT_DATA_ERROR ;
    }

    // set key 
    (void) xqc_aead_crypter_call(builder, set_key, aead_encrypter, key, keylen);
start:
    // do encrypt 
    outlen = builder->xqc_aead_crypter_seal(aead_encrypter, dest, destlen, nonce, noncelen, plaintext, plaintextlen,
        ad, adlen);
    
    if (owns){
        // free encrypter 
        builder->xqc_aead_crypter_free(aead_encrypter);
    }
    return outlen > 0 ? outlen : -XQC_TLS_ENCRYPT_DATA_ERROR;
}

static inline 
ssize_t 
xqc_aead_decrypt(const xqc_aead_t * aead,uint8_t *dest, size_t destlen, 
            const uint8_t *ciphertext,size_t ciphertextlen,
            const uint8_t *key,size_t keylen, 
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen,
            xqc_aead_crypter_t *aead_decrypter)
{
    int owns = 1;
    ssize_t outlen = -1, l ;
    const xqc_aead_crypter_builder_t *builder = aead->aead_crypter_builder ;

    if (aead_decrypter){
        owns = 0 ;
        goto start;
    }
    
    if (XQC_UNLIKELY(!builder)) {
        //TODO 
        return aead->decrypt.xqc_decrypt_func(aead,
                dest,destlen,
                ciphertext,ciphertextlen,
                key,keylen,
                nonce,noncelen,
                ad,adlen);
    }
    
    // new decrypter
    aead_decrypter = builder->xqc_aead_crypter_new(aead,/** enc */ 0); 
    if (XQC_UNLIKELY(!aead_decrypter)) {
        return -XQC_TLS_DECRYPT_DATA_ERROR ;
    }

    // set key 
    (void) xqc_aead_crypter_call(builder, set_key, aead_decrypter, key, keylen);
start:
    // do decrypt 
    outlen = builder->xqc_aead_crypter_open(aead_decrypter, dest, destlen, nonce, noncelen, ciphertext, ciphertextlen,
        ad, adlen);
    
    if (owns){
         // free decrypter 
        builder->xqc_aead_crypter_free(aead_decrypter);
    }
    return outlen > 0 ? outlen : -XQC_TLS_DECRYPT_DATA_ERROR;
}

#endif // XQC_CRYPTO_H_
