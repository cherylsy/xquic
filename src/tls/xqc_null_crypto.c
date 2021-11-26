#include "src/tls/xqc_crypto.h"


static xqc_int_t
xqc_null_aead_encrypt(const xqc_packet_prot_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    if (XQC_LIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }
    *destlen = plaintextlen + xqc_aead_overhead(pp_aead, plaintextlen);

    if (XQC_UNLIKELY(*destlen < 0 || *destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_null_aead_decrypt(const xqc_packet_prot_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    size_t length = ciphertextlen - xqc_aead_overhead(pp_aead, ciphertextlen);
    if (XQC_LIKELY(dest != ciphertext)) {
        memmove(dest, ciphertext, length);
    }
    *destlen = length;

    if (XQC_UNLIKELY(*destlen < 0 || *destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_null_hp_mask(const xqc_header_prot_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    if (XQC_UNLIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }
    *destlen = plaintextlen;

    if (XQC_UNLIKELY(*destlen < 0 || *destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    return XQC_OK;
}


void
xqc_aead_init_null(xqc_packet_prot_aead_t *pp_aead, size_t taglen)
{
    pp_aead->keylen     = 1;
    pp_aead->noncelen   = 1;
    pp_aead->taglen     = taglen;

    pp_aead->xqc_aead_encrypt_func = xqc_null_aead_encrypt;
    pp_aead->xqc_aead_decrypt_func = xqc_null_aead_decrypt;
}

void
xqc_cipher_init_null(xqc_header_prot_cipher_t *hp_cipher)
{
    hp_cipher->keylen   = 1;
    hp_cipher->noncelen = 1;

    hp_cipher->xqc_hp_mask_func    = xqc_null_hp_mask;
}