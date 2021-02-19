#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_config.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_hkdf.h"
#include "src/crypto/xqc_digist.h"
#include "src/crypto/xqc_digist.h"
#include "src/crypto/xqc_crypto.h"


static inline EVP_CIPHER_CTX *
xqc_openssl_cipher_ctx_new(const EVP_CIPHER *cipher, int enc)
{   
    int r;
    if (!cipher){
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (XQC_LIKELY(ctx)){
        r = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, !!enc);
        if (r != XQC_SSL_SUCCESS){
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

/** openssl crypter begin ... */

static xqc_crypter_t *
xqc_openssl_crypter_new(const xqc_crypto_t *crypto, int enc) 
{
    if (XQC_UNLIKELY(!enc)){
        return NULL;
    }
    xqc_crypter_t *crypter = xqc_malloc(sizeof(*crypter));
    if (XQC_LIKELY(crypter)){
        crypter->enc      = !!enc;
        crypter->ctx      = xqc_openssl_cipher_ctx_new(crypto->ctx, crypter->enc);
        crypter->crypto   = crypto;
    }
    return crypter;
}

static void 
xqc_openssl_crypter_free(xqc_crypter_t *crypter) 
{
    if (crypter){
        if(crypter->ctx){
            EVP_CIPHER_CTX_free(crypter->ctx);
        }
        xqc_free(crypter);
    }
}

static ssize_t 
xqc_openssl_crypter_set_key(xqc_crypter_t *crypter, const unsigned char *key, size_t keylen) 
{
    if (crypter && crypter->ctx){
        if (XQC_SSL_SUCCESS == EVP_CipherInit(crypter->ctx, NULL, key, NULL, crypter->enc)){
            return XQC_CRYPTER_SUCCESS;
        }
    }
    return XQC_CRYPTER_FAIL;
}

static ssize_t 
xqc_openssl_crypter_set_nonce(xqc_crypter_t *crypter, const uint8_t *sample, size_t samplelen)
{
    if (crypter && crypter->ctx){
        if (XQC_SSL_SUCCESS == EVP_CipherInit(crypter->ctx, NULL, NULL, sample, crypter->enc)){
            return XQC_CRYPTER_SUCCESS;
        }
    }
    return XQC_CRYPTER_FAIL;
}

static ssize_t 
xqc_openssl_crypter_update(xqc_crypter_t *crypter, uint8_t *dest, size_t destlen, const uint8_t *source, size_t sourcelen)
{
    int outlen = 0;
    ssize_t r;
    if (crypter && crypter->ctx){
        r = crypter->enc ? EVP_EncryptUpdate(crypter->ctx, dest, &outlen, source, sourcelen) 
            : EVP_DecryptUpdate(crypter->ctx, dest, &outlen, source, sourcelen);
        if (XQC_UNLIKELY(r != XQC_SSL_SUCCESS)){
            return XQC_CRYPTER_FAIL;
        }
    }
    return outlen;
}

static ssize_t 
xqc_openssl_crypter_final(xqc_crypter_t *crypter, uint8_t *dest, size_t destlen)
{
    int outlen = 0;
    ssize_t r;
    if (crypter && crypter->ctx){
        r = crypter->enc ? EVP_EncryptFinal(crypter->ctx, dest, &outlen)
            : EVP_DecryptFinal(crypter->ctx, dest, &outlen);
        if (XQC_UNLIKELY(r != XQC_SSL_SUCCESS)){
            return XQC_CRYPTER_FAIL;
        }
    }
    return outlen;
}

xqc_crypter_builder_t xqc_openssl_crypter_builder = {
    .xqc_crypter_new            = xqc_openssl_crypter_new,
    .xqc_crypter_free           = xqc_openssl_crypter_free,
    .xqc_crypter_set_key        = xqc_openssl_crypter_set_key,
    .xqc_crypter_set_nonce      = xqc_openssl_crypter_set_nonce,
    .xqc_crypter_update         = xqc_openssl_crypter_update,
    .xqc_crypter_final          = xqc_openssl_crypter_final,
};

/** ... openssl crypter finish  */


/** openssl aead crypter begin ... */

static xqc_aead_crypter_t* 
xqc_openssl_aead_crypter_new(const xqc_aead_t *aead, int enc)
{
    xqc_aead_crypter_t *aead_crypter = xqc_malloc(sizeof(*aead_crypter));
    if (XQC_LIKELY(aead_crypter)){
        aead_crypter->enc  = !!enc;
        aead_crypter->ctx  = xqc_openssl_cipher_ctx_new(aead->ctx, aead_crypter->enc);
        aead_crypter->aead = aead;
    }
    return aead_crypter;
}

static void
xqc_openssl_aead_crypter_free(xqc_aead_crypter_t *aead_crypter)
{
    if (aead_crypter){
        if (aead_crypter->ctx){
            EVP_CIPHER_CTX_free(aead_crypter->ctx);
        }
        xqc_free(aead_crypter);
    }
}


static ssize_t 
xqc_openssl_aead_crypter_set_key(xqc_aead_crypter_t *aead_crypter, const unsigned char *key, size_t keylen) 
{
    if (aead_crypter && aead_crypter->ctx){
        if (XQC_SSL_SUCCESS == EVP_CipherInit(aead_crypter->ctx, NULL, key, NULL, aead_crypter->enc)){
            return XQC_CRYPTER_SUCCESS;
        }
    }
    return XQC_CRYPTER_FAIL;
}

static ssize_t 
xqc_ossl_aead_encrypt_ex(const xqc_aead_t * aead, EVP_CIPHER_CTX *actx, uint8_t *dest, size_t destlen, const uint8_t *plaintext,
    size_t plaintextlen,  const uint8_t *key,
    size_t keylen, const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = xqc_aead_taglen(aead);
    size_t outlen = 0;
    int len = 0;

    if (destlen <  plaintextlen + xqc_aead_overhead(aead, plaintextlen)){
        return XQC_CRYPTER_FAIL;
    }

    if (actx == NULL){
        return XQC_CRYPTER_FAIL;
    }
    
    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_EncryptInit_ex(actx, NULL, NULL, NULL, nonce) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS){
        goto err ;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += len;

    if (outlen + taglen > destlen){
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += taglen;
    return outlen;
err:
    return XQC_CRYPTER_FAIL;
}


static ssize_t 
xqc_ossl_aead_decrypt_ex(const xqc_aead_t * aead, EVP_CIPHER_CTX *actx, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
    size_t ciphertextlen, const uint8_t *key,
    size_t keylen, const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = xqc_aead_taglen(aead);
    size_t outlen = 0;
    int len = 0;

    if (taglen > ciphertextlen || ciphertextlen > destlen + xqc_aead_overhead(aead, destlen)){
        return XQC_CRYPTER_FAIL;
    }

    ciphertextlen -= taglen;
    uint8_t * tag = (uint8_t *)(ciphertext + ciphertextlen);

    if (actx == NULL){
        return XQC_CRYPTER_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptInit_ex(actx, NULL, NULL, NULL, nonce) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen = len;
    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                (uint8_t *)(tag)) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += len;
    return outlen;
err:
    return XQC_CRYPTER_FAIL;
}


static ssize_t 
xqc_openssl_aead_crypter_operation (xqc_aead_crypter_t *aead_crypter, uint8_t *out, size_t max_out_len, 
    const uint8_t *nonce, size_t nonce_len, 
    const uint8_t *in, size_t in_len,
    const uint8_t *ad, size_t ad_len)
{
    if (XQC_UNLIKELY(!aead_crypter || !aead_crypter->aead)){
        return XQC_CRYPTER_FAIL;
    }

    if (aead_crypter->enc) {
        return xqc_ossl_aead_encrypt_ex(aead_crypter->aead, aead_crypter->ctx,
            out, max_out_len,
            in, in_len,
            NULL, 0,
            nonce, nonce_len,
            ad, ad_len);
    }else {
        return xqc_ossl_aead_decrypt_ex(aead_crypter->aead, aead_crypter->ctx,
            out, max_out_len,
            in, in_len,
            NULL, 0,
            nonce, nonce_len,
            ad, ad_len);
    }
}
 
xqc_aead_crypter_builder_t xqc_openssl_aead_crypter_builder = {
    .xqc_aead_crypter_new           = xqc_openssl_aead_crypter_new,
    .xqc_aead_crypter_free          = xqc_openssl_aead_crypter_free,
    .xqc_aead_crypter_set_key       = xqc_openssl_aead_crypter_set_key,
    .xqc_aead_crypter_operation     = xqc_openssl_aead_crypter_operation,
};

/** ... openssl aead crypter end */

ssize_t
xqc_ossl_crypto_encrypt(const xqc_crypto_t *crypto,
        uint8_t *dest, size_t destlen, 
        const uint8_t *plaintext, size_t plaintextlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen)
{
    size_t outlen = 0;
    int len = 0;

    EVP_CIPHER_CTX  * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL){
        return XQC_CRYPTER_FAIL;
    }

    if (EVP_EncryptInit_ex(actx, crypto->ctx , NULL, key, sample) != XQC_SSL_SUCCESS){
        goto err;
    }


    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen ) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != XQC_SSL_SUCCESS){
        goto err;
    }
#define XQC_CRYPTER_NO_PADDING  (0)
    if (len != XQC_CRYPTER_NO_PADDING){
        goto err;
    }
#undef XQC_CRYPTER_NO_PADDING

    EVP_CIPHER_CTX_free(actx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(actx);
    return XQC_CRYPTER_FAIL;
}

ssize_t 
xqc_ossl_aead_decrypt(const xqc_aead_t *aead, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = xqc_aead_taglen(aead);
    size_t outlen = 0;
    int len = 0;

    if (taglen > ciphertextlen || ciphertextlen > destlen + xqc_aead_overhead(aead,destlen)){
        return XQC_CRYPTER_FAIL;
    }

    ciphertextlen -= taglen;
    uint8_t * tag = (uint8_t *)(ciphertext + ciphertextlen);

    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return XQC_CRYPTER_FAIL;
    }

    if (EVP_DecryptInit_ex(actx,aead->ctx, NULL, NULL, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen = len;
    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                (uint8_t *)(tag)) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += len;

    EVP_CIPHER_CTX_free(actx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(actx);
    return XQC_CRYPTER_FAIL;
}

ssize_t 
xqc_ossl_aead_encrypt(const xqc_aead_t * aead, uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen,  const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{

    ssize_t taglen = xqc_aead_taglen(aead);
    size_t outlen = 0;
    int len = 0;

    if (destlen <  plaintextlen + xqc_aead_overhead(aead, plaintextlen)){
        return XQC_CRYPTER_FAIL;
    }

    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return XQC_CRYPTER_FAIL;
    }
    
    if (EVP_EncryptInit_ex(actx, aead->ctx, NULL, NULL, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }


    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS){
        goto err;
    }

    if (EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != XQC_SSL_SUCCESS){
        goto err;
    }


    if (EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS){
        goto err ;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += len;

    if (outlen + taglen > destlen){
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != XQC_SSL_SUCCESS){
        goto err;
    }

    outlen += taglen;

    EVP_CIPHER_CTX_free(actx);
    return outlen;

err:
    EVP_CIPHER_CTX_free(actx);
    return XQC_CRYPTER_FAIL;
}
