#include "src/crypto/xqc_aead.h"
#include <memory.h>

static 
ssize_t xqc_null_cipher_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_LIKELY(dest != plaintext)) {
        memmove(dest,plaintext,plaintextlen);
    }
    return  plaintextlen + xqc_crypto_overhead(ctx,plaintextlen);
}

static 
ssize_t xqc_null_cipher_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_LIKELY(dest != ciphertext)) {
        memmove(dest,ciphertext,ciphertextlen);
    }
    return ciphertextlen ;
}

static 
ssize_t 
xqc_null_cipher_hp_mask (uint8_t *dest, size_t destlen, const xqc_crypto_t *ctx,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    memcpy(dest,XQC_FAKE_HP_MASK,sizeof(XQC_FAKE_HP_MASK) - 1) ;
    return sizeof(XQC_FAKE_HP_MASK) - 1;
}


void xqc_crypto_init_plaintext(xqc_crypto_t * crypto,size_t taglen) 
{
    if(XQC_LIKELY(crypto)) 
    {
        crypto->aead_ctx = crypto->encrypt.encrypt_ctx = crypto->decrypt.decrypt_ctx = NULL ;
        crypto->keylen = crypto->noncelen = 1 ;
        crypto->taglen = taglen ;
        crypto->encrypt.xqc_encrypt_func    = xqc_null_cipher_encrypt ;
        crypto->decrypt.xqc_decrypt_func    = xqc_null_cipher_decrypt ;
        crypto->hp_mask.xqc_hp_mask_func    = xqc_null_cipher_hp_mask ;
    }
}