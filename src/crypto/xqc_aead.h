#ifndef XQC_AEAD_H_
#define XQC_AEAD_H_

/**
 *  @author 不达 
 * */

#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>


typedef struct xqc_aead_st          xqc_aead_t ;
typedef struct xqc_crypto_st        xqc_crypto_t ;
typedef struct xqc_crypto_hp_st     xqc_crypto_hp_t;


#ifdef OPENSSL_IS_BORINGSSL
#include "src/crypto/boringssl/xqc_aead_impl.h"
#else 
#include "src/crypto/openssl/xqc_aead_impl.h"
#endif 

// obj is (xqc_crypto_t *)
#define XQC_INIT_CRYPTO(obj)                        XQC_INIT_CRYPTO_IMPL((obj))
// obj is (xqc_crypto_hp_t*)
#define XQC_INIT_CRYPTO_HP_MASK(obj)                XQC_INIT_CRYPTO_HP_MASK_IMPL((obj))

// obj is (xqc_aead_t *) 
#define xqc_aead_init_aes_gcm(obj,d)                XQC_AEAD_INIT_AES_GCM_IMPL((obj),d)
#define xqc_aead_init_aes_ctr(obj,d)                XQC_AEAD_INIT_AES_CTR_IMPL((obj),d)
#define xqc_aead_init_chacha20_poly1305(obj,...)    XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL((obj),__VA_ARGS__)

// obj can be any of (xqc_crypto_t * : xqc_crypto_hp_t * :xqc_aead_t*)

// 获取加密算法额外产生的大小开销，特别的当obj==NULL时，总是应返回0 ；
#define xqc_aead_extra_overhead(obj,cln)    XQC_AEAD_EXTRA_OVERHEAD_IMPL(obj,cln)

// 获取算法参数
#define xqc_aead_overhead(obj,cln)          ((obj)->taglen + xqc_aead_extra_overhead((xqc_aead_t*)(obj),cln))
#define xqc_aead_taglen(obj)                ((obj)->taglen)
#define xqc_aead_keylen(obj)                ((obj)->keylen)
#define xqc_aead_noncelen(obj)              ((obj)->noncelen)
// 
#define xqc_aead_ctx(obj)                   XQC_AEAD_CTX_IMPL(obj)

// unused right now 
#define  xqc_cipher_suites_release(obj)      

#endif //XQC_AEAD_H_