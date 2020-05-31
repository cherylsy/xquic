#include <openssl/base.h>
#include <openssl/ssl.h>
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_log.h"
#include "src/crypto/xqc_crypto_material.h"

static 
xqc_int_t 
xqc_generate_initial_secret(const xqc_tls_context_t * ctx , uint8_t * secret , size_t length , xqc_connection_t *conn , xqc_int_t server_secret)
{
    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN]={0} ;
    int rv = 
    xqc_derive_initial_secret(initial_secret, sizeof(initial_secret), &conn->dcid,
            (const uint8_t *)(XQC_INITIAL_SALT),
            strlen(XQC_INITIAL_SALT));
    
    if(XQC_UNLIKELY(rv != 0)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|derive_initial_secret() failed|");
        return 0 ;
    }

    if(server_secret) {
        rv = xqc_derive_server_initial_secret(secret,length,initial_secret,sizeof(initial_secret));
    }else {
        rv = xqc_derive_client_initial_secret(secret,length,initial_secret,sizeof(initial_secret));
    }

    if(XQC_UNLIKELY(rv != 0)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_derive_%s_initial_secret() failed|" , server_secret ? "server" : "client" );
        return 0;
    }

    return 1 ;
}

/**
 *  return one on success 
 * */
static 
xqc_int_t 
xqc_xqc_derive_packet_protection(
    const xqc_tls_context_t * ctx, const uint8_t *secret, size_t secretlen , 
    uint8_t * key , size_t * keylen ,  /** [*len] 是值结果参数 */
    uint8_t * iv , size_t * ivlen   ,
    uint8_t * hp , size_t * hplen   ,
    xqc_log_t * log)
{

    if((*keylen = xqc_derive_packet_protection_key( key, *keylen, secret, secretlen, ctx)) < 0) {
        xqc_log(log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_key failed|ret code:%d|", keylen);
        return 0;
    }

    if((*ivlen = xqc_derive_packet_protection_iv(iv, *ivlen, secret, secretlen, ctx)) < 0 ){
        xqc_log(log, XQC_LOG_ERROR, "|xqc_derive_packet_protection_iv failed| ret code:%d|", ivlen);
        return 0;
    }

    if((*hplen = xqc_derive_header_protection_key(hp, *hplen, secret, secretlen, ctx )) < 0){
        xqc_log(log, XQC_LOG_ERROR, "|xqc_derive_header_protection_key failed| ret code:%d|", hplen);
        return 0;
    }

    return 1;
}

/**
 *  
 * */ 


static 
int 
xqc_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
                        const SSL_CIPHER *cipher, const uint8_t *secret,
                        size_t secretlen)
{

    xqc_connection_t *  conn = (xqc_connection_t *) SSL_get_app_data(ssl);
    xqc_tls_context_t * current_ctx = NULL;

#define XQC_MAX_KNP_LEN  64 
    //TODO need check 64 bytes enough (XQC_MAX_KNP_LEN)
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}, hp[XQC_MAX_KNP_LEN] = {0}; 
    size_t keylen = XQC_MAX_KNP_LEN ,ivlen = XQC_MAX_KNP_LEN , hplen = XQC_MAX_KNP_LEN ;
#undef XQC_MAX_KNP_LEN

    switch(level)
    {
    case ssl_encryption_initial:
    {
        uint8_t private_secret[INITIAL_SECRET_MAX_LEN]={0} ; 
        // 在此处，我们只安装 server 的init rx 和 tx 密钥
        if(conn->conn_type == XQC_CONN_TYPE_SERVER) {

            // 初始化初始密钥套件
            xqc_init_initial_crypto_ctx(conn);
            
            // 初始化服务端密钥
            if(!xqc_generate_initial_secret(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),conn, /** server_secret */ 1)) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_generate_initial_secret failed|");
                return 0 ;
            }
            // 计算服务端密钥套件所需的key nonce 和 hp
            if(!xqc_xqc_derive_packet_protection(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
                // log has done 
                return 0;
            }

            // 设置到 服务端的 tx 
            if( xqc_conn_install_initial_tx_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_conn_install_initial_tx_keys failed|");
                return 0 ;
            }

            // 初始化客户端密钥 
            if(!xqc_generate_initial_secret(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),conn, /** server_secret */ 0)) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_generate_initial_client_secret failed|");
                return 0 ;
            }

            // 重新计算客户端密钥套件所需的key nonce 和 hp
            if(!xqc_xqc_derive_packet_protection(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
                // log has done 
                return 0;
            }

            // 设置到 服务端的 rx
            if( xqc_conn_install_initial_rx_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_conn_install_initial_tx_keys failed|");
                return 0 ;
            }
        }
        // read_secret  我们只安装服务端的init密钥，客户端在write_secret 安装
        return 1;
    }
    case ssl_encryption_early_data:
    case ssl_encryption_handshake :
       if( xqc_init_crypto_ctx (conn,cipher) != 0 ) {
            xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_init_crypto_ctx failed|");
            return 0 ;
        }
        break;
    case ssl_encryption_application : 
    {   
        // store the read secret 
        if(conn->tlsref.rx_secret.base != NULL){ // should xqc_vec_free ? if rx_secret already has value, it means connection status error
            xqc_log(conn->log, XQC_LOG_WARN, "|error rx_secret , may case memory leak |");
        }

        if(xqc_vec_assign(&conn->tlsref.rx_secret, secret, secretlen) < 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "|error assign rx_secret |");
            return 0;
        }
        break;
    }
    }

    // 计算密钥套件所需的key nonce 和 hp
    if(!xqc_xqc_derive_packet_protection(&conn->tlsref.crypto_ctx,secret,secretlen,key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
        // log has done 
        return 0;
    }

    switch(level)
    {
    case ssl_encryption_early_data :
    {
        if(conn->conn_type == XQC_CONN_TYPE_SERVER) {
            if( xqc_conn_install_early_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                return 0 ;
            }
        }
        break ;
    }
    case ssl_encryption_handshake : 
        xqc_conn_install_handshake_rx_keys(conn,key,keylen,iv,ivlen,hp,hplen);
        break;
    case ssl_encryption_application: 
        xqc_conn_install_rx_keys(conn,key,keylen,iv,ivlen,hp,hplen);
        break;
    default:
        // no way 
        return 0 ;
    }

    // return once on success 
    return 1 ;    
}   

static         
int xqc_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
                        const SSL_CIPHER *cipher, const uint8_t *secret,
                        size_t secretlen)
{
    xqc_connection_t *  conn = (xqc_connection_t *) SSL_get_app_data(ssl);

#define XQC_MAX_KNP_LEN  64 
    //TODO need check 64 bytes enough (XQC_MAX_KNP_LEN)
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}, hp[XQC_MAX_KNP_LEN] = {0}; 
    size_t keylen = XQC_MAX_KNP_LEN ,ivlen = XQC_MAX_KNP_LEN , hplen = XQC_MAX_KNP_LEN ;
#undef XQC_MAX_KNP_LEN

    switch(level)
    {
    case ssl_encryption_initial:
    {
        uint8_t private_secret[INITIAL_SECRET_MAX_LEN]={0} ; 
        // 在此处，我们只安装 client 的init rx 和 tx 密钥, 注意这里和 xqc_set_read_secret对应的部分是相反的 。不要尝试合并 
        if(conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            
            xqc_initial_crypto_ctx(conn);
            
            // 初始化服务端密钥
            if(!xqc_generate_initial_secret(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),conn, /** server_secret */ 1)) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_generate_initial_secret failed|");
                return 0 ;
            }
            // 计算服务端密钥套件所需的key nonce 和 hp
            if(!xqc_xqc_derive_packet_protection(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
                // log has done 
                return 0;
            }

            // 设置到 客户端 的 rx 
            if( xqc_conn_install_initial_rx_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_conn_install_initial_tx_keys failed|");
                return 0 ;
            }

            // 初始化客户端密钥 
            if(!xqc_generate_initial_secret(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),conn, /** server_secret */ 0)) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_generate_initial_client_secret failed|");
                return 0 ;
            }

            // 重新计算客户端密钥套件所需的key nonce 和 hp
            if(!xqc_xqc_derive_packet_protection(&conn->tlsref.hs_crypto_ctx,private_secret,sizeof(private_secret),key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
                // log has done 
                return 0;
            }

            // 设置到 客户端的 tx
            if( xqc_conn_install_initial_tx_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_conn_install_initial_tx_keys failed|");
                return 0 ;
            }
        }
        return 1 ;
    }
    case ssl_encryption_early_data:
    case ssl_encryption_handshake:
    {
        if( xqc_init_crypto_ctx (conn,cipher) != 0 ) {
            xqc_log(conn->log,XQC_LOG_ERROR,"|xqc_init_crypto_ctx failed|");
            return 0 ;
        }
        break;
    }
    case ssl_encryption_application : 
    {
        // store the write secret 
        if(conn->tlsref.tx_secret.base != NULL){ // should xqc_vec_free ? if rx_secret already has value, it means connection status error
            xqc_log(conn->log, XQC_LOG_WARN, "|error rx_secret , may case memory leak |");
        }
        if(xqc_vec_assign(&conn->tlsref.tx_secret, secret, secretlen) < 0){
            xqc_log(conn->log, XQC_LOG_ERROR, "|error assign rx_secret |");
            return 0;
        }
        break;
    }
    }

    // 计算密钥套件所需的key nonce 和 hp
    if(!xqc_xqc_derive_packet_protection(&conn->tlsref.crypto_ctx,secret,secretlen,key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
        // log has done 
        return 0;
    }

    switch(level)
    {
    case ssl_encryption_early_data :
    {
        if(conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            if( xqc_conn_install_early_keys(conn,key,keylen,iv,ivlen,hp,hplen) != 0 ) {
                return 0 ;
            }
        }
        break ;
    }
    case ssl_encryption_handshake : 
        xqc_conn_install_handshake_tx_keys(conn,key,keylen,iv,ivlen,hp,hplen);
        break;
    case ssl_encryption_application: 
        xqc_conn_install_tx_keys(conn,key,keylen,iv,ivlen,hp,hplen);
        break;
    default:
        // no way 
        return 0 ;
    }
    // return once on success (boringssl Required)
    return 1 ; 
}

int 
xqc_add_handshake_data (SSL *ssl, enum ssl_encryption_level_t level,
                            const uint8_t *data, size_t len)
{
    xqc_connection_t *  conn = (xqc_connection_t *) SSL_get_app_data(ssl) ;
    xqc_pktns_t * pktns = NULL;

    switch (level)
    {
    case ssl_encryption_initial:
        pktns = &conn->tlsref.initial_pktns;
        break;
    case ssl_encryption_early_data:
        // boringssl不会提供这个等级的数据 
        return 0;
    case ssl_encryption_handshake:
        pktns = &conn->tlsref.hs_pktns;
        break;
    case ssl_encryption_application:
        pktns = &conn->tlsref.pktns ;
        break;
    default:
        // no way , in case of new level 
        return 0;
    }

    // TODO memory optimize 
    xqc_hs_buffer_t *p_data = xqc_create_hs_buffer(len);
    if( XQC_UNLIKELY(!p_data)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_hs_buffer failed|");
        return 0 ;
    }

    memcpy(p_data->data, data, len);
    xqc_list_add_tail(& p_data->list_head, &pktns->msg_cb_head) ;
}

int 
xqc_flush_flight (SSL *ssl)
{
    return 1 ;
}

int 
xqc_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    //xqc_connection_t *  conn = (xqc_connection_t *) SSL_get_app_data(ssl);
    // need finish 
    return 1;
}

static 
SSL_QUIC_METHOD  xqc_ssl_quic_method = 
{
    .set_read_secret    = xqc_set_read_secret ,
    .set_write_secret   = xqc_set_write_secret,
    .add_handshake_data = xqc_add_handshake_data,
    .flush_flight       = xqc_flush_flight,
    .send_alert         = xqc_send_alert,
};


static 
int xqc_do_handshake(xqc_connection_t *conn)
{
    SSL *ssl = conn->xc_ssl ;
    int rv ;
    ERR_clear_error();
again:
    rv = SSL_do_handshake(ssl);
    if(rv <= 0) {
        switch(SSL_get_error(ssl, rv)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            case SSL_ERROR_EARLY_DATA_REJECTED :
            {
                xqc_conn_early_data_reject(conn);
                // reset the state 
                SSL_reset_early_data_reject(ssl);
                xqc_log(conn->log, XQC_LOG_INFO, "| TLS handshake reject 0-RTT :%s|");
                // resume handshake 
                goto again ;
            }
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
        }
    }

    // invoke callback error  
    if( xqc_conn_handshake_completed(conn) != 0 ) {
        return -1 ;
    }
    return 0;
}


/** for xquic */
int 
xqc_client_initial_cb(xqc_connection_t *conn)
{
    SSL * ssl = conn->xc_ssl ;

    if(conn->tlsref.initial) 
    {
        conn->tlsref.initial = 0 ;
        SSL_set_quic_method(ssl,&xqc_ssl_quic_method);
        if(conn->tlsref.resumption) {
            SSL_set_early_data_enabled(ssl,1);
        }
    }

    

    // add_transport_paraments 

    return xqc_do_handshake(conn);
}

int 
xqc_recv_crypto_data_cb2(xqc_connection_t *conn, 
        xqc_encrypt_level_t encrypt_level ,
        uint64_t offset,
        const uint8_t *data, size_t datalen,
        void *user_data)
{

    (void) user_data ;
    (void) offset ;

    SSL * ssl = conn->xc_ssl ;
    if(SSL_provide_quic_data(ssl,encrypt_level,data,datalen) != 1 ) {
        return -1 ;
    }

    if(!xqc_conn_get_handshake_completed(conn)) {
        if(xqc_do_handshake(conn) != 0) {
            return -1;
        }
    }

    return 0 ;
}


int 
xqc_tls_is_early_data_accepted(xqc_connection_t * conn)
{
    if( conn->tlsref.flags & XQC_CONN_FLAG_EARLY_DATA_REJECTED ) { return XQC_TLS_EARLY_DATA_REJECT ;}
    return XQC_TLS_EARLY_DATA_ACCEPT;
}


/** for encrypt or decrypt */

static 
ssize_t xqc_encrypt_impl(const xqc_tls_context_t * ctx ,
    uint8_t *dest,size_t destlen, 
    const uint8_t *plaintext,size_t plaintextlen, 
    const uint8_t *key,size_t keylen, 
    const uint8_t *nonce, size_t noncelen, 
    const uint8_t *ad,size_t adlen,
    void *user_data
)
{

}


static 
ssize_t xqc_decrypt_impl(const xqc_tls_context_t * ctx ,
    uint8_t *dest,size_t destlen, 
    const uint8_t *ciphertext,size_t ciphertextlen, 
    const uint8_t *key,size_t keylen, 
    const uint8_t *nonce, size_t noncelen, 
    const uint8_t *ad,size_t adlen,
    void *user_data
)
{

}

static 
ssize_t xqc_hp_mask_impl(const xqc_tls_context_t * ctx ,
    uint8_t *dest, size_t destlen,
    const uint8_t *key, size_t keylen, const uint8_t *sample,
    size_t samplelen, void *user_data
)
{
    static  uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
    return xqc_encrypt_impl(ctx,dest,destlen,PLAINTEXT,sizeof(PLAINTEXT) - 1 ,key,keylen,sample,samplelen,NULL,0,user_data);
}

ssize_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    return xqc_encrypt_impl(&conn->tlsref.hs_crypto_ctx,dest,destlen,plaintext,plaintextlen,key,keylen,nonce,noncelen,ad,adlen,user_data);
}

ssize_t xqc_do_hs_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    return xqc_decrypt_impl(&conn->tlsref.hs_crypto_ctx,dest,destlen,ciphertext,ciphertextlen,key,keylen,nonce,noncelen,ad,adlen,user_data);
}

ssize_t xqc_do_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    return xqc_encrypt_impl(&conn->tlsref.crypto_ctx,dest,destlen,plaintext,plaintextlen,key,keylen,nonce,noncelen,ad,adlen,user_data);
}

ssize_t xqc_do_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data)
{
    return xqc_decrypt_impl(&conn->tlsref.crypto_ctx,dest,destlen,ciphertext,ciphertextlen,key,keylen,nonce,noncelen,ad,adlen,user_data);
}

ssize_t do_in_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{
    return xqc_hp_mask_impl(&conn->tlsref.hs_crypto_ctx,dest,destlen,key,keylen,sample,samplelen,user_data);
}

ssize_t do_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data)
{
    return xqc_hp_mask_impl(&conn->tlsref.crypto_ctx,dest,destlen,key,keylen,sample,samplelen,user_data);
}