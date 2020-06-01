#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/crypto/xqc_crypto.h"
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

ssize_t xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_crypto_hp_t  *ctx,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen) 
{

    static   uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

    EVP_CIPHER_CTX  * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }


    if (EVP_EncryptInit_ex(actx, xqc_aead_ctx(ctx) , NULL, key, sample) != 1) {
        goto err;
    }

    size_t outlen = 0;
    int len;

    if (EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, sizeof(PLAINTEXT) - 1) !=
            1) {
        goto err;
    }

    //assert(len == 5);
    if(len != 5){
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

//need finish : conn_decrypt_hp only decrypt header protect , not do anything else
static 
ssize_t xqc_conn_decrypt_hp(xqc_connection_t *conn, xqc_pkt_hd *hd,
        uint8_t *dest, size_t destlen,
        const uint8_t *pkt, size_t pktlen,
        size_t pkt_num_offset, unsigned char * hpkey, int hpkey_len,
        xqc_tls_context_t  *ctx, size_t aead_overhead){
    size_t nwrite;
    size_t sample_offset;
    uint8_t *p = dest;
    uint8_t mask[XQC_HP_SAMPLELEN];
    size_t i;

    if (pkt_num_offset + XQC_HP_SAMPLELEN > pktlen) {
        return XQC_ERR_PROTO;
    }

    memcpy(p, pkt, pkt_num_offset);
    p = p + pkt_num_offset;

    sample_offset = pkt_num_offset + 4;

    nwrite =  xqc_hp_mask(mask, sizeof(mask), &ctx->hp, hpkey, hpkey_len, pkt + sample_offset, XQC_HP_SAMPLELEN);
    if (nwrite < XQC_HP_MASKLEN) {
        return XQC_ERR_CALLBACK_FAILURE;
    }

    if (hd->flags & XQC_PKT_FLAG_LONG_FORM) {
        dest[0] = (uint8_t)(dest[0] ^ (mask[0] & 0x0f));
    } else {
        dest[0] = (uint8_t)(dest[0] ^ (mask[0] & 0x1f));
        //if (dest[0] & XQC_SHORT_KEY_PHASE_BIT) {
        //  hd->flags |= XQC_PKT_FLAG_KEY_PHASE;
        //}
    }

    hd->pkt_numlen = (size_t)((dest[0] & XQC_PKT_NUMLEN_MASK) + 1);

    for (i = 0; i < hd->pkt_numlen; ++i) {
        *p++ = *(pkt + pkt_num_offset + i) ^ mask[i + 1];
    }

    int64_t pkt_num = xqc_get_pkt_num(p - hd->pkt_numlen, hd->pkt_numlen);
    if(pkt_num < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|error packet num|");
        return -1;
    }
    hd->pkt_num = pkt_num;

    return p - dest;
}


ssize_t xqc_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_crypto_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen)
{

    ssize_t taglen = xqc_aead_taglen(ctx);

    if (taglen > ciphertextlen || ciphertextlen > destlen + xqc_aead_overhead(ctx,destlen) ) {
        return -1;
    }

    ciphertextlen -= taglen;
    uint8_t * tag = (uint8_t *)(ciphertext + ciphertextlen);

    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }

    if (EVP_DecryptInit_ex(actx,xqc_aead_ctx(ctx), NULL, NULL, NULL) != 1) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) !=
            1) {
        goto err;
    }

    if (EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        goto err;
    }

    size_t outlen;
    int len;

    if (EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        goto err;
    }

    if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
        goto err;
    }

    outlen = len;

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                (uint8_t *)(tag)) != 1) {
        goto err;
    }

    if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto err;
    }

    outlen += len;

    EVP_CIPHER_CTX_free(actx);
    return outlen;

    //auto actx_d = defer(EVP_CIPHER_CTX_free, actx);
err:
    EVP_CIPHER_CTX_free(actx);
    return -1;
}

ssize_t 
xqc_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, const xqc_crypto_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) 
{

    ssize_t taglen = xqc_aead_taglen(ctx);
    // not enough space 
    if( destlen <  plaintextlen + xqc_aead_overhead(ctx,plaintextlen) ) {
        return -1;
    }

    // TODO 
    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }
    
    if (EVP_EncryptInit_ex(actx, xqc_aead_ctx(ctx) , NULL, NULL, NULL) != 1) {
        goto err;
    }

    // TODO 
    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) !=
            1) {
        goto err;
    }

    if (EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        goto err;
    }

    size_t outlen = 0;
    int len;

    if(EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != 1){
        goto err ;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto err;
    }

    outlen += len;

    //assert(outlen + taglen <= destlen);
    if(outlen + taglen > destlen){
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != 1) {
        goto err;
    }

    outlen += taglen;

    EVP_CIPHER_CTX_free(actx);
    return outlen;

err:
    EVP_CIPHER_CTX_free(actx);
    return -1;
}
















