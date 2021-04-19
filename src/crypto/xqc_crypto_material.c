#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_hkdf.h"
#include "src/crypto/xqc_digist.h"
#include "src/crypto/xqc_crypto.h"
#include "src/common/xqc_defs.h"

/** private */

static
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

int
xqc_negotiated_aead_and_prf(xqc_tls_context_t *ctx, uint32_t cipher_id)
{
    switch(cipher_id)
    {
        case 0x03001301u: // TLS_AES_128_GCM_SHA256
            xqc_aead_init_aes_gcm(&ctx->aead, 128);
            xqc_crypto_init_aes_ctr(&ctx->crypto, 128);
            xqc_digist_init_to_sha256(&ctx->prf);
            return 0;
        case 0x03001302u: // TLS_AES_256_GCM_SHA384
            xqc_aead_init_aes_gcm(&ctx->aead, 256);
            xqc_crypto_init_aes_ctr(&ctx->crypto, 256);
            xqc_digist_init_to_sha384(&ctx->prf);
            return 0;
        case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
            xqc_aead_init_chacha20_poly1305(&ctx->aead);
            xqc_crypto_init_chacha20(&ctx->crypto);
            xqc_digist_init_to_sha256(&ctx->prf);
            return 0;
        case NID_undef:
            xqc_aead_init_null(&ctx->aead, XQC_FAKE_AEAD_OVERHEAD);
            xqc_crypto_init_null(&ctx->crypto);
            xqc_digist_init_to_sha256(&ctx->prf);
            return 0;
        default: //TLS_AES_128_CCM_SHA256、TLS_AES_128_CCM_8_SHA256 not support
            return -1;
    }
}

static inline
xqc_int_t 
xqc_complete_crypto_ctx(xqc_tls_context_t * ctx,uint32_t cipher_id,xqc_int_t no_crypto)
{
    cipher_id = (no_crypto) ? NID_undef : cipher_id ;
    return xqc_negotiated_aead_and_prf(ctx,cipher_id);
}

/** private end */

void 
xqc_init_initial_crypto_ctx(xqc_connection_t * conn)
{
    xqc_tls_context_t * ctx = &conn->tlsref.hs_crypto_ctx;
    // 从之前的实现看，inittial加密等级会无视no crypto 。
    (void) xqc_complete_crypto_ctx(ctx,0x03001301u,/** no crypto */ 0);
}

xqc_int_t 
xqc_init_crypto_ctx(xqc_connection_t * conn,const SSL_CIPHER * cipher) 
{
    if(XQC_LIKELY(cipher)) {
        xqc_tls_context_t * ctx = &conn->tlsref.crypto_ctx ;
        const uint32_t cipher_id = SSL_CIPHER_get_id(cipher) ;
        if (ctx->aead.ctx == NULL) {
            if(xqc_complete_crypto_ctx(ctx, cipher_id, conn->local_settings.no_crypto) != 0){
                goto err ;
            }
        }
        return 0 ;
    }
err:
    return -1 ; 
}

xqc_int_t
xqc_setup_crypto_ctx(xqc_connection_t * conn, xqc_encrypt_level_t level, const uint8_t *secret, size_t secretlen,
    uint8_t *key, size_t *keylen,  /** [*len] 是值结果参数 */
    uint8_t *iv, size_t *ivlen,
    uint8_t *hp, size_t *hplen)
{
    uint32_t cipher_id ;

    if (XQC_UNLIKELY(!conn || level >= XQC_ENC_MAX_LEVEL)) {
        return -XQC_EPARAM ;
    }

    xqc_tls_context_t *ctx = & conn->tlsref.crypto_ctx_store[level];    
    
    switch (level)
    {
    case XQC_ENC_LEV_INIT:
        cipher_id = 0x03001301u ;
        break;
    case XQC_ENC_LEV_0RTT:
    case XQC_ENC_LEV_1RTT:
        // only data use no crypto 
        cipher_id = conn->local_settings.no_crypto ? NID_undef : SSL_CIPHER_get_id(SSL_get_current_cipher(conn->xc_ssl));
        break;
    case XQC_ENC_LEV_HSK:
    default:
        cipher_id = SSL_CIPHER_get_id(SSL_get_current_cipher(conn->xc_ssl));
        break;
    }

    if (xqc_negotiated_aead_and_prf(ctx, cipher_id) == XQC_OK) {
        // 计算密钥套件所需的key nonce 和 hp
        if (xqc_derive_packet_protection(ctx, secret, secretlen, key, keylen, iv, ivlen, hp, hplen, conn->log) == XQC_SSL_SUCCESS) {
            return XQC_OK ; 
        }           
    }
    
    return -XQC_TLS_CRYPTO_CTX_NEGOTIATED_ERROR ;
}

int xqc_derive_initial_secret(uint8_t *dest, size_t destlen,
        const  xqc_cid_t *cid, const uint8_t *salt,
        size_t saltlen)
{
    xqc_digist_t md ;
    xqc_digist_init_to_sha256(&md);
    return xqc_hkdf_extract(dest, destlen, cid->cid_buf, cid->cid_len, salt,
            saltlen, &md);
}

int xqc_derive_client_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen) 
{
    static   uint8_t LABEL[] = "client in";
    xqc_digist_t md ;
    xqc_digist_init_to_sha256(&md);
    return xqc_hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
            strlen(LABEL), &md);
}

int xqc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen) 
{
    static   uint8_t LABEL[] = "server in";
    xqc_digist_t md ;
    xqc_digist_init_to_sha256(&md);
    return xqc_hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
            strlen(LABEL), &md);
}

ssize_t xqc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) 
{
    int rv;
    static   uint8_t LABEL[] = "quic iv";

    
    ssize_t ivlen = xqc_max(8, xqc_crypto_iv_length(&ctx->aead));
    if (ivlen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, ivlen, secret, secretlen, LABEL,
            strlen(LABEL), &ctx->prf);
    if (rv != 0) {
        return -1;
    }

    return ivlen;
}

ssize_t xqc_derive_header_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) 
{
    int rv;
    static   uint8_t LABEL[] = "quic hp";

    ssize_t keylen = xqc_crypto_key_length(&ctx->crypto);
    if (keylen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
            strlen(LABEL), &ctx->prf);

    if (rv != 0) {
        return -1;
    }

    return keylen;
}


ssize_t xqc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
        const uint8_t *secret, size_t secretlen,
        const xqc_tls_context_t *ctx) 
{
    int rv;
    static   uint8_t LABEL[] = "quic key";

    ssize_t keylen = xqc_crypto_key_length(&ctx->aead);
    if (keylen > destlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
            strlen(LABEL), &ctx->prf);
    if (rv != 0) {
        return -1;
    }

    return keylen;
}


int xqc_conn_install_initial_tx_keys(xqc_connection_t *conn,  uint8_t *key,
                                        size_t keylen,  uint8_t *iv,
                                        size_t ivlen,  uint8_t *pn,
                                        size_t pnlen)
{
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
                                        size_t pnlen)
{
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
                                   size_t pnlen) 
{

    if(conn->tlsref.early_hp.base != NULL && conn->tlsref.early_hp.len > 0){
        return -XQC_TLS_INVALID_STATE;
    }

    if(conn->tlsref.early_ckm.key.base != NULL && conn->tlsref.early_ckm.key.len > 0){
        return -XQC_TLS_INVALID_STATE;
    }

    if(conn->tlsref.early_ckm.iv.base != NULL && conn->tlsref.early_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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



int xqc_conn_install_handshake_tx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen) 
{
    xqc_pktns_t *pktns = &conn->tlsref.hs_pktns;
    int rv;

    if (pktns->tx_hp.base != NULL && pktns->tx_hp.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->tx_ckm.iv.base != NULL && pktns->tx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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

int xqc_conn_install_handshake_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv,
        size_t ivlen, const uint8_t *pn,
        size_t pnlen) 
{
    xqc_pktns_t *pktns = &conn->tlsref.hs_pktns;
    int rv;

    if (pktns->rx_hp.base != NULL && pktns->rx_hp.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->rx_ckm.iv.base != NULL && pktns->rx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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


int xqc_conn_install_tx_keys(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen,
                                const uint8_t *pn, size_t pnlen) 
{
    xqc_pktns_t *pktns = &conn->tlsref.pktns;
    int rv;

    if (pktns->tx_hp.base != NULL && pktns->tx_hp.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->tx_ckm.key.base != NULL && pktns->tx_ckm.key.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->tx_ckm.iv.base != NULL && pktns->tx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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

int xqc_conn_install_rx_keys(xqc_connection_t *conn, const uint8_t *key,
        size_t keylen, const uint8_t *iv, size_t ivlen,
        const uint8_t *pn, size_t pnlen) 
{

    xqc_pktns_t *pktns = &conn->tlsref.pktns;
    int rv;

    if (pktns->rx_hp.base != NULL && pktns->rx_hp.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0) {
        return -XQC_TLS_INVALID_STATE;
    }
    if(pktns->rx_ckm.iv.base != NULL && pktns->rx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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


int xqc_update_traffic_secret(uint8_t *dest, size_t destlen, uint8_t *secret,
        ssize_t secretlen, const xqc_tls_context_t *ctx)
{

    uint8_t LABEL[] = "traffic upd";
    int rv;
    if (destlen < secretlen) {
        return -1;
    }

    rv = xqc_hkdf_expand_label(dest, secretlen, secret, secretlen, LABEL, strlen(LABEL), &ctx->prf );
    if(rv < 0){
        return -1;
    }

    return secretlen;
}



int xqc_conn_update_tx_key(xqc_connection_t *conn, const uint8_t *key,
                                size_t keylen, const uint8_t *iv, size_t ivlen) 
{
    int rv;
    xqc_tlsref_t * tlsref = &conn->tlsref;

    if(tlsref->flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        return -XQC_TLS_INVALID_STATE;
    }

    if(tlsref->new_tx_ckm.key.base != NULL && tlsref->new_tx_ckm.key.len > 0){
        return -XQC_TLS_INVALID_STATE;
    }

    if(tlsref->new_tx_ckm.iv.base != NULL && tlsref->new_tx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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
                                size_t keylen, const uint8_t *iv, size_t ivlen) 
{

    int rv;
    xqc_tlsref_t * tlsref = &conn->tlsref;

    if(tlsref->flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
        return -XQC_TLS_INVALID_STATE;
    }

    if(tlsref->new_rx_ckm.key.base != NULL && tlsref->new_rx_ckm.key.len > 0){
        return -XQC_TLS_INVALID_STATE;
    }

    if(tlsref->new_rx_ckm.iv.base != NULL && tlsref->new_rx_ckm.iv.len > 0){
        return -XQC_TLS_INVALID_STATE;
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



int xqc_recv_client_hello_derive_key( xqc_connection_t *conn, xqc_cid_t *dcid )
{
    int rv;

    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN]={0}, secret[INITIAL_SECRET_MAX_LEN]={0};

    if (!xqc_check_proto_version_valid(conn->version)) {
        return -XQC_TLS_PROTO;
    }

    rv = xqc_derive_initial_secret(
            initial_secret, sizeof(initial_secret), dcid,
            (const uint8_t *)(xqc_crypto_initial_salt[conn->version]),
            strlen(xqc_crypto_initial_salt[conn->version]));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive_initial_secret() failed|");
        return -1;
    }

    xqc_init_initial_crypto_ctx(conn);

    rv = xqc_derive_server_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive_server_initial_secret() failed|");
        return -1;
    }

    char key[16], iv[16], hp[16];

    ssize_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        return -1;
    }

    ssize_t ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed|");
        return -1;
    }

    ssize_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key failed|");
        return -1;
    }
    //need log

    if(xqc_conn_install_initial_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|install initial key error|");
        return -1;
    }

    rv = xqc_derive_client_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_client_initial_secret error|");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key error|");
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv error|");
        return -1;
    }

    hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key error|");
        return -1;
    }

    if(xqc_conn_install_initial_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_install_initial_rx_keys error|");
        return -1;
    }

    return 0;
}


/*
 * notice: return one on success, return 0 on fail
 */
xqc_int_t
xqc_derive_packet_protection(
    const xqc_tls_context_t *ctx, const uint8_t *secret, size_t secretlen,
    uint8_t *key, size_t *keylen,  /** [*len] 是值结果参数 */
    uint8_t *iv, size_t *ivlen,
    uint8_t *hp, size_t *hplen,
    xqc_log_t *log)
{
    ssize_t kl = xqc_derive_packet_protection_key(key, *keylen, 
        secret, secretlen, ctx);
    if (kl < 0) {
        xqc_log(log, XQC_LOG_ERROR, 
                "|xqc_derive_packet_protection_key failed|ret code:%d|", keylen);
        return XQC_SSL_FAIL;
    }
    *keylen = kl;

    ssize_t ivl = xqc_derive_packet_protection_iv(iv, *ivlen, 
                                                  secret, secretlen, ctx);
    if (ivl < 0) {
        xqc_log(log, XQC_LOG_ERROR, 
                "|xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return XQC_SSL_FAIL;
    }
    *ivlen = ivl;

    ssize_t hpl = xqc_derive_header_protection_key(hp, *hplen, secret, 
        secretlen, ctx);
    if (hpl < 0) {
        xqc_log(log, XQC_LOG_ERROR, 
                "|xqc_derive_header_protection_key failed| ret code:%d|", hplen);
        return XQC_SSL_FAIL;
    }
    *hplen = hpl;

    return XQC_SSL_SUCCESS;
}
