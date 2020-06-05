#include "src/crypto/xqc_crypto.h"
#include <memory.h>



static
ssize_t 
xqc_null_aead_encrypt(const xqc_aead_t * ctx,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_LIKELY(dest != plaintext)) {
        memmove(dest,plaintext,plaintextlen);
    }
    return plaintextlen + xqc_crypto_overhead(ctx,plaintextlen);
}

static
ssize_t
xqc_null_aead_decrypt(const xqc_aead_t * ctx,uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    size_t length = ciphertextlen - xqc_crypto_overhead(ctx,ciphertextlen);
    if(XQC_LIKELY(dest != ciphertext)) {
        memmove(dest,ciphertext,length);
    }
    return length;
}

static 
ssize_t 
xqc_null_cipher_encrypt(const xqc_crypto_t *ctx,uint8_t *dest, size_t destlen, 
            const uint8_t *plaintext,size_t plaintextlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    if(XQC_UNLIKELY(dest != plaintext)) {
        memmove(dest,plaintext,plaintextlen);
    }
    return plaintextlen;
}


xqc_int_t 
xqc_aead_init_null(xqc_aead_t * aead,size_t taglen) 
{
    aead->keylen = aead->noncelen = 1 ;
    aead->taglen = taglen ;
    aead->encrypt.xqc_encrypt_func  = xqc_null_aead_encrypt ;
    aead->decrypt.xqc_decrypt_func  = xqc_null_aead_decrypt ;
    return 0;
}

xqc_int_t 
xqc_crypto_init_null(xqc_crypto_t * crypto)
{
    crypto->keylen = crypto->noncelen = 1 ;
    crypto->encrypt.xqc_encrypt_func = xqc_null_cipher_encrypt;
    return 0;
}