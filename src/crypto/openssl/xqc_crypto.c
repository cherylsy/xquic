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



int64_t xqc_get_pkt_num(const uint8_t *p, size_t pkt_numlen) 
{
    switch (pkt_numlen) {
        case 1:
            return *p;
        case 2:
            return xqc_get_uint16(p);
        case 3:
            return xqc_get_uint24(p);
        case 4:
            return xqc_get_uint32(p);
        default:
            //assert(0);
            return -1;
    }
}

ssize_t
xqc_ossl_crypto_encrypt(const xqc_crypto_t *crypto,
        uint8_t *dest,size_t destlen, 
        const uint8_t *plaintext,size_t plaintextlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen)
{
    EVP_CIPHER_CTX *actx = NULL;
    ssize_t ret = -1;
    do {
        actx = EVP_CIPHER_CTX_new();
        if (actx == NULL) {
            break;
        }

        if (EVP_EncryptInit_ex(actx, crypto->ctx , NULL, key, sample) != 1) {
            break;
        }

        size_t outlen = 0;
        int len = 0;
        if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
            break;
        }

        outlen = len;
        if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
            break;
        }

        if (len != 0) {
            break;
        }

        ret = outlen;
    } while (0);

    if (NULL != actx) {
        EVP_CIPHER_CTX_free(actx);
        actx = NULL;
    }

    return ret;
}

ssize_t 
xqc_ossl_aead_decrypt(const xqc_aead_t *aead, uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen,const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = xqc_aead_taglen(aead);
    if (taglen > ciphertextlen || ciphertextlen > destlen + xqc_aead_overhead(aead,destlen)) {
        return -1;
    }

    ssize_t ret = -1;

    ciphertextlen -= taglen;
    uint8_t * tag = (uint8_t *)(ciphertext + ciphertextlen);
    EVP_CIPHER_CTX *actx = NULL;
    do {
        actx = EVP_CIPHER_CTX_new();
        if (actx == NULL) {
            return -1;
        }

        if (EVP_DecryptInit_ex(actx,aead->ctx, NULL, NULL, NULL) != 1) {
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
            break;
        }

        if (EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
            break;
        }

        ssize_t outlen = 0;
        int len = 0;
        if (EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
            break;
        }

        if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
            break;
        }

        outlen = len;
        if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                    (uint8_t *)(tag)) != 1) {
            break;
        }

        if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
            break;
        }

        outlen += len;
        ret = outlen;
    } while (0);

    EVP_CIPHER_CTX_free(actx);
    return ret;
}

ssize_t 
xqc_ossl_aead_encrypt(const xqc_aead_t * aead,uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen,  const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = xqc_aead_taglen(aead);
    // not enough space 
    if( destlen <  plaintextlen + xqc_aead_overhead(aead,plaintextlen) ) {
        return -1;
    }

    ssize_t ret = -1;
    EVP_CIPHER_CTX *actx = NULL;
    do {
        actx = EVP_CIPHER_CTX_new();
        if (actx == NULL) {
            break;
        }

        if (EVP_EncryptInit_ex(actx, aead->ctx, NULL, NULL, NULL) != 1) {
            break;
        }

        // TODO 
        if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
            break;
        }

        if (EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
            break;
        }

        ssize_t outlen = 0;
        int len = 0;
        if(EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != 1){
            break;
        }

        if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
            break;
        }

        outlen = len;
        if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
            break;
        }

        outlen += len;
        if (outlen + taglen > destlen) {
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != 1) {
            break;
        }

        outlen += taglen;
        ret = outlen;
    } while (0);

    if (NULL == actx) {
        EVP_CIPHER_CTX_free(actx);
        actx = NULL;
    }
    return ret;
}
















