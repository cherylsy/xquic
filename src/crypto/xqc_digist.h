#ifndef XQC_DIGIST_H_
#define XQC_DIGIST_H_

#include <openssl/evp.h>

typedef struct xqc_digist_st xqc_digist_t ;
struct xqc_digist_st 
{
    const EVP_MD * digist ;
};

#define xqc_digist_init_to_sha256(obj)  ((obj)->digist = EVP_sha256())

#define xqc_digist_init_to_sha384(obj)  ((obj)->digist = EVP_sha384())

#endif // 