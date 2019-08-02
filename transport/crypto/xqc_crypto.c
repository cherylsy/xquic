#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include "xqc_crypto.h"
#include "xqc_tls_public.h"
#include "transport/xqc_conn.h"
#include "common/xqc_config.h"
#include "xqc_tls_cb.h"

#define XQC_FAKE_AEAD_OVERHEAD 16

/*xqc_negotiated_prf stores the negotiated PRF(pseudo random function) by TLS into ctx.
 *@param
 *@return 0 if it succeeds, or -1.
 */
int xqc_negotiated_prf(xqc_tls_context_t * ctx, SSL *ssl){
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
        case 0x03001301u: // TLS_AES_128_GCM_SHA256
        case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
            ctx->prf = EVP_sha256();
            return 0;
        case 0x03001302u: // TLS_AES_256_GCM_SHA384
            ctx->prf = EVP_sha384();
            return 0;
        default:  //TLS_AES_128_CCM_SHA256、TLS_AES_128_CCM_8_SHA256 not support
            return -1;
    }
}

/*xqc_negotiated_aead stores the negotiated AEAD by TLS into |ctx|.
 *@return returns 0 if it succeeds, or -1.
 */
int xqc_negotiated_aead(xqc_tls_context_t *ctx, SSL *ssl) {
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
        case 0x03001301u: // TLS_AES_128_GCM_SHA256
            ctx->aead = EVP_aes_128_gcm();
            ctx->hp = EVP_aes_128_ctr();
            return 0;
        case 0x03001302u: // TLS_AES_256_GCM_SHA384
            ctx->aead = EVP_aes_256_gcm();
            ctx->hp = EVP_aes_256_ctr();
            return 0;
        case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
            ctx->aead = EVP_chacha20_poly1305();
            ctx->hp = EVP_chacha20();
            return 0;
        default: //TLS_AES_128_CCM_SHA256、TLS_AES_128_CCM_8_SHA256 not support
            return -1;
    }
    return -1;
}

uint64_t xqc_get_pkt_num(const uint8_t *p, size_t pkt_numlen) {
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
            assert(0);
    }
}

void xqc_conn_set_aead_overhead(xqc_connection_t *conn, size_t aead_overhead) {
    conn->tlsref.aead_overhead = aead_overhead;
}

static size_t xqc_aead_tag_length(const xqc_tls_context_t *ctx) {
    if (ctx->aead == EVP_aes_128_gcm() || ctx->aead == EVP_aes_256_gcm()) {
        return EVP_GCM_TLS_TAG_LEN;
    }
    if (ctx->aead == EVP_chacha20_poly1305()) {
        return EVP_CHACHAPOLY_TLS_TAG_LEN;
    }
    assert(0);
}

size_t xqc_aead_max_overhead(const xqc_tls_context_t *ctx) { return xqc_aead_tag_length(ctx); }

int xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *salt, size_t saltlen,
        const xqc_tls_context_t *ctx) {
    EVP_PKEY_CTX * pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) != 1) {
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx -> prf) != 1) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
err:
    EVP_PKEY_CTX_free(pctx);
    return -1;
}


int xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *info, size_t infolen,
                const xqc_tls_context_t *ctx) {
  EVP_PKEY_CTX * pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (pctx == NULL) {
    return -1;
  }

  if (EVP_PKEY_derive_init(pctx) != 1) {
    goto err;
  }

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
    goto err;
  }

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1) {
    goto err;
  }

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1) {
    goto err;
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
    goto err;
  }

  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1) {
    goto err;
  }

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    goto err;
  }

  return 0;

err:
    EVP_PKEY_CTX_free(pctx);
    return -1;
}


int xqc_hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *label, size_t labellen,
        const xqc_tls_context_t *ctx) {

    unsigned char  info[256];
    static const uint8_t LABEL[] = "tls13 ";

    unsigned char * p = info;
    *p++ = destlen / 256;
    *p++ = destlen % 256;
    *p++ = strlen(LABEL) + labellen;
    p = xqc_cpymem(p, LABEL, strlen(LABEL));
    p = xqc_cpymem(p, label, labellen);
    *p++ = 0;

    return xqc_hkdf_expand(dest, destlen, secret, secretlen, info, p - info, ctx); // p-info 存疑,need finish

}

void xqc_prf_sha256(xqc_tls_context_t *ctx) { ctx->prf = EVP_sha256(); }//指定sha256散列算法

void xqc_aead_aes_128_gcm(xqc_tls_context_t *ctx) {
    ctx->aead = EVP_aes_128_gcm();
    ctx->hp = EVP_aes_128_ctr();
}

size_t xqc_aead_key_length(const xqc_tls_context_t *ctx) {
    return EVP_CIPHER_key_length(ctx->aead);
}

size_t xqc_aead_nonce_length(const xqc_tls_context_t *ctx) {
    return EVP_CIPHER_iv_length(ctx->aead);
}

int xqc_derive_initial_secret(uint8_t *dest, size_t destlen,
        const  xqc_cid_t *cid, const uint8_t *salt,
        size_t saltlen){
    xqc_tls_context_t ctx;
    xqc_prf_sha256(&ctx);
    return xqc_hkdf_extract(dest, destlen, cid->cid_buf, cid->cid_len, salt,
            saltlen, &ctx);

}

int xqc_derive_client_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen) {
    static   uint8_t LABEL[] = "client in";
    xqc_tls_context_t ctx;
    xqc_prf_sha256(&ctx);
    return xqc_hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
            strlen(LABEL), &ctx);
}

int xqc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen) {
    static   uint8_t LABEL[] = "server in";
    xqc_tls_context_t ctx;
    xqc_prf_sha256(&ctx);
    return xqc_hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
            strlen(LABEL), &ctx);
}


size_t xqc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) {
    int rv;
    static   uint8_t LABEL[] = "quic key";

    size_t keylen = xqc_aead_key_length(ctx);
    if (keylen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
            strlen(LABEL), ctx);
    if (rv != 0) {
        return -1;
    }

    return keylen;
}



size_t xqc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) {
    int rv;
    static   uint8_t LABEL[] = "quic iv";

    size_t ivlen = xqc_max(8, xqc_aead_nonce_length(ctx));
    if (ivlen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, ivlen, secret, secretlen, LABEL,
            strlen(LABEL), ctx);
    if (rv != 0) {
        return -1;
    }

    return ivlen;
}


size_t xqc_derive_header_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) {
    int rv;
    static   uint8_t LABEL[] = "quic hp";

    size_t keylen = xqc_aead_key_length(ctx);
    if (keylen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
            strlen(LABEL), ctx);

    if (rv != 0) {
        return -1;
    }

    return keylen;
}

#define XQC_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

size_t xqc_no_hp_mask(uint8_t *dest, size_t destlen, const xqc_tls_context_t *ctx,
                const uint8_t *key, size_t keylen, const uint8_t *sample,
                size_t samplelen) {

  memcpy(dest, XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK) - 1);
  return sizeof(XQC_FAKE_HP_MASK) - 1;
}

size_t xqc_hp_mask(uint8_t *dest, size_t destlen, const xqc_tls_context_t  *ctx,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen) {
    static   uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

    EVP_CIPHER_CTX  * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(actx, ctx->hp, NULL, key, sample) != 1) {
        goto err;
    }

    size_t outlen = 0;
    int len;

    if (EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, sizeof(PLAINTEXT) - 1) !=
            1) {
        goto err;
    }

    assert(len == 5);

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto err;
    }

    assert(len == 0);

    EVP_CIPHER_CTX_free(actx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(actx);
    return -1;
}

//need finish : conn_decrypt_hp only decrypt header protect , not do anything else
static size_t xqc_conn_decrypt_hp(xqc_connection_t *conn, xqc_pkt_hd *hd,
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

    nwrite =  xqc_hp_mask(mask, sizeof(mask), ctx, hpkey, hpkey_len, pkt + sample_offset, XQC_HP_SAMPLELEN);
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

    hd->pkt_num = xqc_get_pkt_num(p - hd->pkt_numlen, hd->pkt_numlen);

    return p - dest;
}


ssize_t xqc_no_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) {
    memmove(dest, ciphertext, ciphertextlen - XQC_FAKE_AEAD_OVERHEAD);
    return (size_t)ciphertextlen - XQC_FAKE_AEAD_OVERHEAD;
}

size_t xqc_decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen){
    size_t taglen = xqc_aead_tag_length(ctx);

    if (taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
        return -1;
    }

    ciphertextlen -= taglen;
    uint8_t * tag = (uint8_t *)(ciphertext + ciphertextlen);

    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }


    if (EVP_DecryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1) {
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


size_t xqc_no_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) {

    return (size_t)plaintextlen + XQC_FAKE_AEAD_OVERHEAD;
}

size_t xqc_encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
        size_t plaintextlen, const xqc_tls_context_t *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) {
    int taglen = xqc_aead_tag_length(ctx);

    if (destlen < plaintextlen + taglen) {
        return -1;
    }

    EVP_CIPHER_CTX * actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }


    if (EVP_EncryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) !=
            1) {
        goto err;
    }

    if (EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        goto err;
    }

    size_t outlen = 0;
    int len;

    if (EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        goto err;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto err;
    }

    outlen += len;

    assert(outlen + taglen <= destlen);

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


void xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen,
        uint64_t pkt_num) {
    size_t i;

    memcpy(dest, iv, ivlen);
    pkt_num = bswap64(pkt_num);

    for (i = 0; i < 8; ++i) {
        dest[ivlen - 8 + i] ^= ((uint8_t *)&pkt_num)[i];
    }
}




int xqc_crypto_km_new(xqc_crypto_km_t * p_ckm, const uint8_t *key,
                                 size_t keylen, const uint8_t *iv, size_t ivlen){

    if(xqc_vec_assign(&p_ckm->key, key, keylen) < 0){
        return -1;
    }

    if(xqc_vec_assign(&p_ckm->iv, iv, ivlen) < 0){
        return -1;
    }

    p_ckm->pkt_num = 0;
    p_ckm->flags = XQC_CRYPTO_KM_FLAG_NONE;
    return 0;

}

int xqc_conn_install_initial_tx_keys(xqc_connection_t *conn,  uint8_t *key,
                                        size_t keylen,  uint8_t *iv,
                                        size_t ivlen,  uint8_t *pn,
                                        size_t pnlen){
    xqc_pktns_t * pktns = & conn->tlsref.initial_pktns;
    int rv;

    if(pktns->tx_hp.base != NULL && pktns->tx_hp.len > 0){
        xqc_vec_free(&pktns->tx_hp);
    }

    if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0){
        xqc_vec_free(&pktns->tx_ckm.key);
    }

    if(pktns->tx_ckm.iv.base != NULL && pktns->tx_ckm.iv.len > 0){
        xqc_vec_free(&pktns->tx_ckm.iv);
    }

    if(xqc_vec_assign(&pktns->tx_hp, pn, pnlen) < 0){
        return -1;
    }

    if(xqc_vec_assign(&pktns->tx_ckm.key, key, keylen) < 0){
        return -1;
    }

    if(xqc_vec_assign(&pktns->tx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }

    return 0;
}


int xqc_conn_install_initial_rx_keys(xqc_connection_t *conn,  uint8_t *key,
                                        size_t keylen, uint8_t *iv,
                                        size_t ivlen, uint8_t *pn,
                                        size_t pnlen){
    xqc_pktns_t * pktns = & conn->tlsref.initial_pktns;
    int rv;

    if(pktns->rx_hp.base != NULL && pktns->rx_hp.len > 0){
        xqc_vec_free(&pktns->rx_hp);
    }

    if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0){
        xqc_vec_free(&pktns->rx_ckm.key);
    }

    if(pktns->rx_ckm.iv.base != NULL && pktns->rx_ckm.iv.len > 0){
        xqc_vec_free(&pktns->rx_ckm.iv);
    }

    if(xqc_vec_assign(&pktns->rx_hp, pn, pnlen) < 0){
        return -1;
    }

    if(xqc_vec_assign(&pktns->rx_ckm.key, key, keylen) < 0){
        return -1;
    }

    if(xqc_vec_assign(&pktns->rx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }

    return 0;
}


int xqc_conn_install_early_keys(xqc_connection_t *conn, const uint8_t *key,
                                   size_t keylen, const uint8_t *iv,
                                   size_t ivlen, const uint8_t *pn,
                                   size_t pnlen) {
    if(conn->tlsref.early_hp.base != NULL && conn->tlsref.early_hp.len > 0){
        return XQC_ERR_INVALID_STATE;
    }

    if(conn->tlsref.early_ckm.key.base != NULL && conn->tlsref.early_ckm.key.len > 0){
        return XQC_ERR_INVALID_STATE;
    }

    if(conn->tlsref.early_ckm.iv.base != NULL && conn->tlsref.early_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    if(xqc_vec_assign(& conn->tlsref.early_hp, pn, pnlen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& conn->tlsref.early_ckm.key, key, keylen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& conn->tlsref.early_ckm.iv, iv, ivlen) < 0) {
        return -1;
    }

    return 0;
}

int xqc_conn_install_handshake_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen) {
    xqc_pktns_t *pktns = &conn->tlsref.hs_pktns;
    int rv;

    if (pktns->rx_hp.base != NULL && pktns->rx_hp.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->rx_ckm.iv.base != NULL && pktns->rx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }

    //need finish refresh crypto_rx_offset_base
    //conn->hs_pktns.crypto_rx_offset_base = conn->crypto.last_rx_offset;

    if(xqc_vec_assign(& pktns->rx_hp, pn, pnlen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->rx_ckm.key, key, keylen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->rx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }
    return 0;
}


int xqc_conn_install_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv, size_t ivlen,
        const uint8_t *pn, size_t pnlen) {

    xqc_pktns_t *pktns = &conn->tlsref.pktns;
    int rv;

    if (pktns->rx_hp.base != NULL && pktns->rx_hp.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->rx_ckm.iv.base != NULL && pktns->rx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    /* TODO This must be done once */
    //need finish refresh crypto_rx_offset_base
    //if (conn->pktns.crypto_rx_offset_base == 0) {
    //  conn->pktns.crypto_rx_offset_base = conn->crypto.last_rx_offset;
    //}
    if(xqc_vec_assign(& pktns->rx_hp, pn, pnlen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->rx_ckm.key, key, keylen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->rx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }
    return 0;

}

int xqc_conn_install_handshake_tx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen) {
    xqc_pktns_t *pktns = &conn->tlsref.hs_pktns;
    int rv;

    if (pktns->tx_hp.base != NULL && pktns->tx_hp.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->tx_ckm.iv.base != NULL && pktns->tx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    if(xqc_vec_assign(& pktns->tx_hp, pn, pnlen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->tx_ckm.key, key, keylen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->tx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }
    return 0;
}

int xqc_conn_install_tx_keys(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen,
                                const uint8_t *pn, size_t pnlen) {
    xqc_pktns_t *pktns = &conn->tlsref.pktns;
    int rv;

    if (pktns->tx_hp.base != NULL && pktns->tx_hp.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0) {
        return XQC_ERR_INVALID_STATE;
    }
    if(pktns->tx_ckm.iv.base != NULL && pktns->tx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    if(xqc_vec_assign(& pktns->tx_hp, pn, pnlen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->tx_ckm.key, key, keylen) < 0){
        return -1;
    }
    if(xqc_vec_assign(& pktns->tx_ckm.iv, iv, ivlen) < 0){
        return -1;
    }
    return 0;
}

int xqc_update_traffic_secret(uint8_t *dest, size_t destlen, uint8_t *secret,
        size_t secretlen, const xqc_tls_context_t *ctx){

    uint8_t LABEL[] = "traffic upd";
    int rv;
    if (destlen < secretlen) {
        printf("update traffic secret error\n");
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, secretlen, secret, secretlen, LABEL, strlen(LABEL), ctx);
    if(rv < 0){

        printf("update traffic secret hkdf expand error\n");
        return -1;
    }

    return secretlen;
}



int xqc_conn_update_tx_key(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen) {
    int rv;
    xqc_tlsref_t * tlsref = &conn->tlsref;

    if(tlsref->flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        return XQC_ERR_INVALID_STATE;
    }

    if(tlsref->new_tx_ckm.key.base != NULL && tlsref->new_tx_ckm.key.len > 0){
        return XQC_ERR_INVALID_STATE;
    }

    if(tlsref->new_tx_ckm.iv.base != NULL && tlsref->new_tx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    if(xqc_crypto_km_new(& tlsref->new_tx_ckm, key, keylen, iv, ivlen) < 0){
        return -1;
    }

    xqc_pktns_t *pktns = &conn->tlsref.pktns;

    if (!(pktns->tx_ckm.flags & XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE)) {
        tlsref->new_tx_ckm.flags |= XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE;
    }

    return 0;
}

int xqc_conn_update_rx_key(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen) {

    int rv;
    xqc_tlsref_t * tlsref = &conn->tlsref;

    if(tlsref->flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        return XQC_ERR_INVALID_STATE;
    }

    if(tlsref->new_rx_ckm.key.base != NULL && tlsref->new_rx_ckm.key.len > 0){
        return XQC_ERR_INVALID_STATE;
    }

    if(tlsref->new_rx_ckm.iv.base != NULL && tlsref->new_rx_ckm.iv.len > 0){
        return XQC_ERR_INVALID_STATE;
    }


    if(xqc_crypto_km_new(& tlsref->new_rx_ckm, key, keylen, iv, ivlen) < 0){
        return -1;
    }

    xqc_pktns_t *pktns = &conn->tlsref.pktns;

    if (!(pktns->rx_ckm.flags & XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE)) {
        tlsref->new_rx_ckm.flags |= XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE;
    }

    return 0;

    //need finish
}

