#ifndef XQC_CRYPTO_MATERIAL_H_
#define XQC_CRYPTO_MATERIAL_H_

#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>
#include "src/crypto/xqc_tls_if.h"


void xqc_init_initial_crypto_ctx(xqc_connection_t * conn);
/** 
 * 目前 application 和 handhsake 总是共用一套加密套件 
 * early_data 可能会出现 不一致的情况。
 * */
xqc_int_t xqc_init_crypto_ctx(xqc_connection_t * conn,const SSL_CIPHER * cipher);

// Configure encryption algorithms at different stages within the connection
xqc_int_t  xqc_setup_crypto_ctx(xqc_connection_t * conn,xqc_encrypt_level_t level,const uint8_t *secret, size_t secretlen,
        uint8_t *key, size_t *keylen,  /** [*len] 是值结果参数 */
        uint8_t *iv, size_t *ivlen,
        uint8_t *hp, size_t *hplen);

int xqc_derive_initial_secret(uint8_t *dest, size_t destlen,
        const  xqc_cid_t *cid, const uint8_t *salt,
        size_t saltlen);

int xqc_derive_client_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen);

int xqc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen);


// 我们需要利用ctx->prf算法进行hkdf操作，这意味着算法得到的最大的key是 ctx->prf算法的最大输出。
// 如 sha1 -> 20 ; sha128 -> 16 ; sha256 -> 32 ; sha384->64 ; poly1305 -> 
// 调用者需要确保destlen >= output_len(ctx->prf) >= key_len(ctx->aead)


ssize_t xqc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);

ssize_t xqc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);

ssize_t xqc_derive_header_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx);



// install initial receive keys to connection 
//  return ZERO if success 
int xqc_conn_install_initial_rx_keys(xqc_connection_t *conn, uint8_t *key,
                                        size_t keylen,  uint8_t *iv,
                                        size_t ivlen, uint8_t *pn,
                                        size_t pnlen);

// install initial write keys to connection 
//  return ZERO if success 
int xqc_conn_install_initial_tx_keys(xqc_connection_t *conn, uint8_t *key,
                                        size_t keylen, uint8_t *iv,
                                        size_t ivlen,  uint8_t *pn,
                                        size_t pnlen);


// install early key to connetion
// return ZERO if success 
int xqc_conn_install_early_keys(xqc_connection_t *conn, const uint8_t *key,
                                   size_t keylen, const uint8_t *iv,
                                   size_t ivlen, const uint8_t *pn,
                                   size_t pnlen);



// install handshake receive keys to connection 
//  return ZERO if success 
int xqc_conn_install_handshake_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen);

// install handshake write keys to connection 
// return ZERO if success 
int xqc_conn_install_handshake_tx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen);


// install 1-rtt receive keys to connection 
// return ZERO if success 
int xqc_conn_install_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv, size_t ivlen,
        const uint8_t *pn, size_t pnlen);



// install 1-rtt write keys to connection 
// return ZERO if success 
int xqc_conn_install_tx_keys(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen,
                                const uint8_t *pn, size_t pnlen);


// update traffic secret 
// return ZERO if success 
int xqc_update_traffic_secret(uint8_t *dest, size_t destlen, uint8_t *secret,
        ssize_t secretlen, const xqc_tls_context_t *ctx);

// call after xqc_update_traffic_secret to update recevie traffic key
// return ZERO if success 
int xqc_conn_update_rx_key(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen);

// call after xqc_update_traffic_secret to update write traffic key
// return ZERO if success 
int xqc_conn_update_tx_key(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen);



/** -------utils---------*/

int xqc_recv_client_hello_derive_key( xqc_connection_t *conn, xqc_cid_t *dcid );

xqc_int_t xqc_derive_packet_protection(
    const xqc_tls_context_t *ctx, const uint8_t *secret, size_t secretlen,
    uint8_t *key, size_t *keylen,  /** [*len] 是值结果参数 */
    uint8_t *iv, size_t *ivlen,
    uint8_t *hp, size_t *hplen,
    xqc_log_t *log);

int xqc_negotiated_aead_and_prf(xqc_tls_context_t *ctx, uint32_t cipher_id);

#endif //XQC_CRYPTO_MATERIAL_H_
