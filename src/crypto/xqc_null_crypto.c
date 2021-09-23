#include "src/crypto/xqc_crypto.h"
#include "src/common/xqc_malloc.h"
#include <memory.h>

/** null crypter begin ... */

static xqc_crypter_t *
xqc_null_crypter_new (const xqc_crypto_t *crypto, int enc)
{
    xqc_crypter_t * crypter = xqc_malloc(sizeof(*crypter));
    if (XQC_LIKELY(crypter)) {
        crypter->crypto = crypto;
        crypter->enc    = !!enc;
    }
    return crypter;
}

static void 
xqc_null_crypter_free (xqc_crypter_t *crypter)
{
    if (XQC_LIKELY(crypter)) {
        xqc_free(crypter);
    }
}

static ssize_t 
xqc_null_crypter_update (xqc_crypter_t *crypter, uint8_t *dest, size_t destlen,
    const uint8_t *source, size_t sourcelen) 
{
    if (XQC_UNLIKELY(dest != source)) {
        memmove(dest, source, sourcelen);
    }
    return sourcelen; 
}

static ssize_t 
xqc_null_crypter_final (xqc_crypter_t *ctx, uint8_t *dest, size_t destlen)
{
    return 0;
}

/**
 *  default null crypter builder 
 * */
xqc_crypter_builder_t xqc_null_crypter = {
    .xqc_crypter_new          = xqc_null_crypter_new ,
    .xqc_crypter_free         = xqc_null_crypter_free,
    .xqc_crypter_set_key      = NULL,
    .xqc_crypter_set_nonce    = NULL,
    .xqc_crypter_update       = xqc_null_crypter_update,
    .xqc_crypter_final        = xqc_null_crypter_final,
};

/** ... null crypter finish */

/** null aead crypter begin ... */

static xqc_aead_crypter_t * 
xqc_null_aead_crypter_new (const xqc_aead_t *aead, int enc)
{
    xqc_aead_crypter_t* aead_crypter = xqc_malloc(sizeof(*aead_crypter));
    if (XQC_LIKELY(aead_crypter)) {
        aead_crypter->aead  = aead;
        aead_crypter->enc   = !!enc;
    }
    return aead_crypter;
}

static void
xqc_null_aead_crypter_free (xqc_aead_crypter_t *aead_crypter)
{
    if (XQC_LIKELY(aead_crypter)) {
        xqc_free(aead_crypter);
    }
}

static ssize_t
xqc_null_aead_crypter_operation (xqc_aead_crypter_t *aead_crypter,
    uint8_t *out, size_t max_out_len, 
    const uint8_t *nonce, size_t nonce_len, 
    const uint8_t *in, size_t in_len,
    const uint8_t *ad, size_t ad_len)
{
    size_t taglen ;
    ssize_t outlen;

    if (XQC_UNLIKELY(!aead_crypter)) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    taglen = aead_crypter->aead->taglen;
    
    if (aead_crypter->enc) {
        outlen  = in_len + taglen;

    }else {
        in_len  -= taglen;
        outlen  = in_len;
    }

    if (XQC_UNLIKELY(outlen < 0 || outlen > max_out_len)) {
        return -XQC_TLS_INTERNAL;
    }

    if (XQC_LIKELY(in != out)) {
        memmove(out, in, in_len);
    }

    return outlen;
}


xqc_aead_crypter_builder_t xqc_null_aead_crypter = {
    .xqc_aead_crypter_new         = xqc_null_aead_crypter_new,
    .xqc_aead_crypter_free        = xqc_null_aead_crypter_free,
    .xqc_aead_crypter_operation   = xqc_null_aead_crypter_operation,
};

/** ... null aead crypter finish */


static ssize_t 
xqc_null_aead_encrypt(const xqc_aead_t * ctx,
    uint8_t *dest, size_t destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    if (XQC_LIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }
    return plaintextlen + xqc_aead_overhead(ctx, plaintextlen);
}

static ssize_t
xqc_null_aead_decrypt(const xqc_aead_t * ctx,
    uint8_t *dest, size_t destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    size_t length = ciphertextlen - xqc_aead_overhead(ctx, ciphertextlen);
    if (XQC_LIKELY(dest != ciphertext)) {
        memmove(dest, ciphertext, length);
    }
    return length;
}

static ssize_t 
xqc_null_cipher_encrypt(const xqc_crypto_t *ctx,
    uint8_t *dest, size_t destlen, 
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    if (XQC_UNLIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }
    return plaintextlen;
}


xqc_int_t 
xqc_aead_init_null(xqc_aead_t *aead, size_t taglen) 
{
    aead->keylen = aead->noncelen = 1 ;
    aead->taglen = taglen ;
    aead->aead_crypter_builder      = &xqc_null_aead_crypter;
    aead->encrypt.xqc_encrypt_func  = xqc_null_aead_encrypt ;
    aead->decrypt.xqc_decrypt_func  = xqc_null_aead_decrypt ;
    return 0;
}

xqc_int_t 
xqc_crypto_init_null(xqc_crypto_t *crypto)
{
    crypto->keylen = crypto->noncelen   = 1 ;
    crypto->encrypt.xqc_encrypt_func    = xqc_null_cipher_encrypt;
    crypto->crypter_builder             = &xqc_null_crypter;
    return 0;
}