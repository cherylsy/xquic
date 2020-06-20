#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/aead.h>
#include <openssl/evp.h>

/**
 * @author 不达 
 * */

#ifndef XQC_CRYPTO_PRIVAYE
#error "不要单独include，直接include crypto.h"
#endif


#define XQC_CRYPTO_CTX_TYPE_IMPL const EVP_CIPHER * 

#define XQC_AEAD_CTX_TYPE_IMPL   const EVP_AEAD *


// 目前我们所实现的所有的cipher都是不需要额外填充的。
#define  XQC_CIPHER_OVERHEAD_IMPL(obj,cln)         (0)
// 目前我们所实现的所有的cipher都是不需要额外填充的,因此overhead总是等于tag的长度。
#define  XQC_AEAD_OVERHEAD_IMPL(obj,cln)           (0) + (obj)->taglen


#define DO_NOT_CALL_XQC_AEAD_INIT(obj,a)        ({                              \
    obj->ctx            = a ;                                                   \
    obj->taglen         = EVP_AEAD_max_tag_len(obj->ctx);                       \
    obj->keylen         = EVP_AEAD_key_length(obj->ctx);                        \
    obj->noncelen       = EVP_AEAD_nonce_length(obj->ctx);                      \
    obj->encrypt.xqc_encrypt_func = xqc_bssl_aead_encrypt;                      \
    obj->decrypt.xqc_decrypt_func = xqc_bssl_aead_decrypt;                      \
    0;})                               

#define DO_NOT_CALL_XQC_CRYPTO_INIT(obj,c)        ({                            \
    obj->ctx            = c;                                                    \
    obj->keylen         = EVP_CIPHER_key_length(obj->ctx);                      \
    obj->noncelen       = EVP_CIPHER_iv_length(obj->ctx);                       \
    0;})

#define XQC_AEAD_INIT_AES_GCM_IMPL(obj,d,...)   ({                              \
    xqc_aead_t * ___aead    = (obj);                                            \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_aead_aes_##d##_gcm());                \
    0;})

#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj,...) ({                        \
    xqc_aead_t * ___aead = (obj);                                               \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead,EVP_aead_chacha20_poly1305());            \
    0;})

#define XQC_CRYPTO_INIT_AES_CTR_IMPL(obj,d,...) ({                      \
    xqc_crypto_t * ___crypto = (obj);                                   \
    DO_NOT_CALL_XQC_CRYPTO_INIT(___crypto,EVP_aes_##d##_ctr());         \
    ___crypto->encrypt.xqc_encrypt_func = xqc_bssl_crypto_encrypt;      \
    0;})

//注意，boringssl的chacha20实现并未提供EVP_chacha20,我们需要利用Crypto_chacha20实现。
//基于openssl的实现，我们这里需要使用16个字节的nonce，其中前4字节作为Crypto_chacha20算法的counter，后12字节作为其nonce 。
#define XQC_CRYPTO_INIT_CHACHA20_IMPL(obj,...)  ({                          \
    xqc_crypto_t * ___crypto = (obj);                                       \
    ___crypto->keylen     = 32 ;                                            \
    ___crypto->noncelen   = 16;                                             \
    ___crypto->encrypt.xqc_encrypt_func = xqc_bssl_crypto_chacha20_encrypt;  \
    0;})

/** extern */

ssize_t 
xqc_bssl_aead_decrypt(const xqc_aead_t *ctx, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen,const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen);

ssize_t 
xqc_bssl_aead_encrypt(const xqc_aead_t *ctx,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen,  const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) ;

ssize_t
xqc_bssl_crypto_encrypt(const xqc_crypto_t*ctx,uint8_t *dest, size_t destlen, 
        const uint8_t *plaintext,size_t plaintextlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen);

ssize_t 
xqc_bssl_crypto_chacha20_encrypt(const xqc_crypto_t * crypto,
            uint8_t *dest, size_t destlen,
            const uint8_t *plaintext,size_t plaintextlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen);


#endif //XQC_AEAD_IMPL_H_