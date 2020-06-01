#include "src/crypto/xqc_crypto.h"
#include <memory.h>

ssize_t xqc_null_cipher_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
            size_t plaintextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    if(XQC_LIKELY(dest != plaintext)) {
        memmove(dest,plaintext,plaintextlen);
    }
    return  plaintextlen + xqc_aead_overhead(ctx,plaintextlen);
}

ssize_t xqc_null_cipher_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
            size_t ciphertextlen, const xqc_crypto_t * ctx, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, size_t noncelen,
            const uint8_t *ad, size_t adlen)
{
    size_t length = ciphertextlen - xqc_aead_overhead(ctx,ciphertextlen);
    if(XQC_LIKELY(dest != ciphertext)) {
        memmove(dest,ciphertext,length);
    }
    return length;
}

ssize_t 
xqc_null_cipher_hp_mask (uint8_t *dest, size_t destlen, const xqc_crypto_hp_t *ctx,
            const uint8_t *key, size_t keylen, const uint8_t *sample,
            size_t samplelen)
{
    memcpy(dest,XQC_FAKE_HP_MASK,sizeof(XQC_FAKE_HP_MASK) - 1) ;
    return sizeof(XQC_FAKE_HP_MASK) - 1;
}
