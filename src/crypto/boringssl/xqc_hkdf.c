#include "src/crypto/xqc_hkdf.h"
#include <openssl/hkdf.h>
#include <openssl/err.h>
#include <openssl/chacha.h>

// return ZERO on success 
int xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *salt, size_t saltlen,
        const xqc_digist_t *md) 
{

    int rv = HKDF_extract(dest,&destlen,md->digist,secret,secretlen,salt,saltlen);
    if(rv != 1) {
        return -1;
    }
    return 0;
}

// return ZERO on success 
int xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *info, size_t infolen,
        const xqc_digist_t *md) 
{
    int rv = HKDF_expand(dest,destlen,md->digist,secret,secretlen,info,infolen);
    if(rv != 1) 
    {
        return -1;
    }
    return 0;
}
