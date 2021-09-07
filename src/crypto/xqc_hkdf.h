#ifndef XQC_HKDF_H_
#define XQC_HKDF_H_

#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_digist.h"


// return ZERO on success 
int xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *salt, size_t saltlen,
        const xqc_digist_t *md) ;

// return ZERO on success 
int xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *info, size_t infolen,
        const xqc_digist_t *md) ;


// return ZERO on success 
int xqc_hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *label, size_t labellen,
        const xqc_digist_t *md) ;
#endif