#include "src/crypto/xqc_hkdf.h"
#include <openssl/kdf.h>


int xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *info, size_t infolen,
        const xqc_digist_t *ctx) 
{
    
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

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digist) != 1) {
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

    if(pctx){
        EVP_PKEY_CTX_free(pctx);
    }
    return 0;

err:
    if(pctx){
        EVP_PKEY_CTX_free(pctx);
    }
    return -1;
}


int xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *salt, size_t saltlen,
        const xqc_digist_t *ctx) {
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

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digist) != 1) {
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

