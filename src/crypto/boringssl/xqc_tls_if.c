#include <openssl/base.h>
#include <openssl/ssl.h>
#include "src/crypto/xqc_tls_if.h"
#include "src/transport/xqc_conn.h"
#include "src/crypto/xqc_crypto.h"
#include "src/crypto/xqc_tls_init.h"
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_log.h"
#include "src/crypto/xqc_crypto_material.h"
#include "src/crypto/xqc_tls_cb.h"
#include "src/crypto/xqc_transport_params.h"
#include "src/crypto/xqc_tls_stack_cb.h"

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
    if(!xqc_derive_packet_protection(&conn->tlsref.crypto_ctx,secret,secretlen,key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
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
    if(!xqc_derive_packet_protection(&conn->tlsref.crypto_ctx,secret,secretlen,key,&keylen,iv,&ivlen,hp,&hplen,conn->log)) {
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
    return 1;
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
int xqc_configure_quic(xqc_connection_t *conn)
{
    SSL *ssl = conn->xc_ssl ;
    const unsigned char  *out;
    size_t  outlen;
    int rv ;

    SSL_set_quic_method(ssl,&xqc_ssl_quic_method);
    SSL_set_early_data_enabled(ssl,1);
    
    
    switch(conn->conn_type)
    {
    case XQC_CONN_TYPE_CLIENT:{
        rv = xqc_serialize_client_transport_params(conn,XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,&out,&outlen);
        if(rv != 0) {
            return rv ;
        }
        break;
    }
    case XQC_CONN_TYPE_SERVER:{
        rv = xqc_serialize_server_transport_params(conn,XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,&out,&outlen);
        SSL_set_quic_early_data_context(ssl,out,outlen);
        if(rv != 0) {
            return rv;
        }
        break;
    }
    }
    rv = SSL_set_quic_transport_params(ssl,out,outlen);
    // free it 
    xqc_transport_parames_serialization_free((void*)out);
    // boringssl call return 1 on success  while xqc_call return 0 on success , weird 
    if(rv != 1) {
        return -1 ;
    }
    return 0;
}

static 
int xqc_do_handshake(xqc_connection_t *conn)
{
    SSL *ssl = conn->xc_ssl ;
    int rv ;
again:
    ERR_clear_error();
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
                // reset the state 
                SSL_reset_early_data_reject(ssl);
                xqc_log(conn->log, XQC_LOG_INFO, "| TLS handshake reject 0-RTT|");
                // resume handshake 
                goto again ;
            }
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
        }
    }

    // 如果是因early data提前握手结束，则需要继续。但是此时early data 密钥已经准备就绪。
    if(SSL_in_early_data(ssl)) {
        return 0;
    }

    const uint8_t * peer_transport_params ;
    size_t outlen;
    SSL_get_peer_quic_transport_params(ssl,&peer_transport_params,&outlen);
    
    if(XQC_LIKELY(outlen > 0)) 
    {
        if(conn->conn_type == XQC_CONN_TYPE_SERVER) {
            xqc_on_server_recv_peer_transport_params(conn,peer_transport_params,outlen);
        }else {
            xqc_on_client_recv_peer_transport_params(conn,peer_transport_params,outlen);
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
    if(conn->tlsref.initial) {
        conn->tlsref.initial = 0 ;
        xqc_configure_quic(conn);
    }
    
    return xqc_do_handshake(conn);
}

static 
enum ssl_encryption_level_t convert_to_bssl_level(xqc_encrypt_level_t level)
{
    switch(level)
    {
    case XQC_ENC_LEV_INIT :
        return ssl_encryption_initial ;
    case XQC_ENC_LEV_0RTT :
        return ssl_encryption_early_data;
    case XQC_ENC_LEV_HSK  :
        return ssl_encryption_handshake ;
    case XQC_ENC_LEV_1RTT:
    default:
        return ssl_encryption_application;
    }
}

int 
xqc_recv_crypto_data_cb(xqc_connection_t *conn, 
        uint64_t offset,
        const uint8_t *data, size_t datalen,
        xqc_encrypt_level_t encrypt_level ,
        void *user_data)
{
    if(conn->tlsref.initial) {
        conn->tlsref.initial = 0 ;
        xqc_configure_quic(conn);
    }

    (void) user_data ;
    (void) offset ;

    SSL * ssl = conn->xc_ssl ;
    if( SSL_provide_quic_data(ssl,convert_to_bssl_level(encrypt_level),data,datalen) != 1 ) {
        xqc_log(conn->log,XQC_LOG_ERROR,"| SSL_provide_quic_data failed[level:%d]|",encrypt_level);
        return -1 ;
    }
    
    if( !xqc_conn_get_handshake_completed(conn) ) {
        if(xqc_do_handshake(conn) != 0) {
            xqc_log(conn->log,XQC_LOG_ERROR,"| xqc_do_handshake failed |");
            return -1;
        }
    }else 
    {
        if( SSL_process_quic_post_handshake(ssl) != 1 ) {
            xqc_log(conn->log,XQC_LOG_ERROR,"| SSL_process_quic_post_handshake failed |");
            return -1;
        }
    }

    return 0 ;
}


int 
xqc_tls_is_early_data_accepted(xqc_connection_t * conn)
{
    if(conn->conn_type == XQC_CONN_TYPE_CLIENT && !conn->tlsref.resumption) {
        return XQC_TLS_NO_EARLY_DATA ;
    }

    if(SSL_early_data_accepted(conn->xc_ssl)) {
        return XQC_TLS_EARLY_DATA_ACCEPT ;
    }else {
        return XQC_TLS_EARLY_DATA_REJECT;
    }
}

int xqc_recv_client_initial_cb(xqc_connection_t * conn,
        xqc_cid_t *dcid,
        void *user_data)
{
    return xqc_recv_client_hello_derive_key(conn, dcid);
}
