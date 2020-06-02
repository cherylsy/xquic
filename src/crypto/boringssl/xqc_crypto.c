#include "src/crypto/xqc_crypto.h"

#include <openssl/chacha.h>

ssize_t 
xqc_bssl_aead_decrypt(const xqc_aead_t * aead, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen,const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{
    EVP_AEAD_CTX * decrypt = EVP_AEAD_CTX_new(aead->ctx,key,keylen,aead->taglen);
    size_t outlen;
    int rv = EVP_AEAD_CTX_open(decrypt,dest,&outlen,destlen,nonce,noncelen,ciphertext,ciphertextlen,ad,adlen);
    if(rv != 1) {
        return -1;
    }
    return outlen;
}

ssize_t 
xqc_bssl_aead_encrypt(const xqc_aead_t * aead,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen,  const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) 
{
    EVP_AEAD_CTX * encrypt = EVP_AEAD_CTX_new(aead->ctx,key,keylen,aead->taglen);
    size_t outlen;
    int rv = EVP_AEAD_CTX_seal(encrypt,dest,&outlen,destlen,nonce,noncelen,plaintext,plaintextlen,ad,adlen);
    if(rv != 1) {
        return -1;
    }
    return  outlen;
}

ssize_t
xqc_bssl_crypto_encrypt(const xqc_crypto_t*crypto, uint8_t *dest, size_t destlen, 
        const uint8_t *plaintext,size_t plaintextlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen)
{
    EVP_CIPHER_CTX  * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(actx, crypto->ctx , NULL, key, sample) != 1) {
        goto err;
    }

    size_t outlen = 0;
    int len;

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen ) !=
            1) {
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto err;
    }

    //assert(len == 0);
    if(len != 0){
        goto err;
    }

    EVP_CIPHER_CTX_free(actx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(actx);
    return -1;
}

ssize_t 
xqc_bssl_crypto_chacha20_encrypt(const xqc_crypto_t * crypto,
            uint8_t *dest, size_t destlen,
            const uint8_t *plaintext,size_t plaintextlen,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    // unused 
    (void) crypto ;
    if(XQC_UNLIKELY(keylen != 32 && samplelen != 16)) {
        return -1;
    }
    uint32_t * counter = (uint32_t *) (sample) ;
    sample += sizeof(uint32_t);
    CRYPTO_chacha_20(dest,plaintext,plaintextlen,key,sample,*counter);
    return plaintextlen;
}


// ssize_t 
// xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_crypto_hp_t  *ctx,
//         const uint8_t *key, size_t keylen, const uint8_t *sample,
//         size_t samplelen)
// {
//     EVP_AEAD_CTX * encrypt = EVP_AEAD_CTX_new(xqc_aead_ctx(ctx),key,keylen,ctx->taglen);
//     size_t outlen;
//     int rv = EVP_AEAD_CTX_seal(encrypt,dest,&outlen,destlen,sample,samplelen,XQC_FAKE_HP_MASK,sizeof(XQC_FAKE_HP_MASK)-1,NULL,0);
//     if(rv != 1 || outlen != 5) {
//         return -1;
//     }
//     return outlen;
// }


// ssize_t xqc_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
//         size_t ciphertextlen, const xqc_crypto_t *ctx, const uint8_t *key,
//         size_t keylen, const uint8_t *nonce, size_t noncelen,
//         const uint8_t *ad, size_t adlen)
// {
//     EVP_AEAD_CTX * decrypt = EVP_AEAD_CTX_new(xqc_aead_ctx(ctx),key,keylen,ctx->taglen);
//     size_t outlen;
//     int rv = EVP_AEAD_CTX_open(decrypt,dest,&outlen,destlen,nonce,noncelen,ciphertext,ciphertextlen,ad,adlen);
//     if(rv != 1) {
//         return -1;
//     }
//     return outlen;
// }
 
// ssize_t 
// xqc_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
//         size_t plaintextlen, const xqc_crypto_t *ctx, const uint8_t *key,
//         size_t keylen, const uint8_t *nonce, size_t noncelen,
//         const uint8_t *ad, size_t adlen) 
// {
//     EVP_AEAD_CTX * encrypt = EVP_AEAD_CTX_new(xqc_aead_ctx(ctx),key,keylen,ctx->taglen);
//     size_t outlen;
//     int rv = EVP_AEAD_CTX_seal(encrypt,dest,&outlen,destlen,nonce,noncelen,plaintext,plaintextlen,ad,adlen);
//     if(rv != 1) {
//         return -1;
//     }
//     return  outlen;
// }
