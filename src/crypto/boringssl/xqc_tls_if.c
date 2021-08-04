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
        // ssl_encryption_early_data is unaviable for xqc_add_handshake_data 
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

static SSL_QUIC_METHOD  xqc_ssl_quic_method = {
    .set_read_secret    = xqc_set_read_secret ,
    .set_write_secret   = xqc_set_write_secret,
    .add_handshake_data = xqc_add_handshake_data,
    .flush_flight       = xqc_flush_flight,
    .send_alert         = xqc_send_alert,
};


void 
xqc_set_ssl_quic_method(SSL * ssl)
{
    SSL_set_quic_method(ssl, &xqc_ssl_quic_method);
}


static int 
xqc_configure_quic(xqc_connection_t *conn)
{
    SSL *ssl = conn->xc_ssl ;
    const unsigned char  *out;
    size_t  outlen;
    int rv ;

    SSL_set_early_data_enabled(ssl, 1);

    SSL_set_quic_use_legacy_codepoint(conn->xc_ssl, conn->version != XQC_VERSION_V1);

    switch(conn->conn_type)
    {
    case XQC_CONN_TYPE_CLIENT:{
        rv = xqc_serialize_client_transport_params(conn,
                            XQC_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
                            &out, &outlen);
        if (rv != XQC_OK) {
            return rv;
        }
        break;
    }
    case XQC_CONN_TYPE_SERVER:{
        rv = xqc_serialize_server_transport_params(conn,
                            XQC_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
                            &out, &outlen);
        if (rv != XQC_OK) {
            return rv;
        }
        break;
    }
    }
    rv = SSL_set_quic_transport_params(ssl,out,outlen);
    // free it 
    xqc_transport_parames_serialization_free((void*)out);

    if (rv != XQC_SSL_SUCCESS) {
        return -XQC_TLS_SET_TRANSPORT_PARAM_ERROR;
    }

    return XQC_OK;
}

static int 
xqc_do_handshake(xqc_connection_t *conn)
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
                xqc_log(conn->log, XQC_LOG_INFO, "|TLS handshake reject 0-RTT|");
                // resume handshake 
                goto again ;
            }
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|TLS handshake error:%s|", ERR_error_string(ERR_get_error(), NULL));
                return -1;
        }
    }

    // early return  
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

xqc_int_t 
xqc_tls_recv_crypto_data_cb(xqc_connection_t *conn, 
    const unsigned char *data_pos, size_t data_len, xqc_encrypt_level_t encrypt_level)
{
    if (conn->tlsref.initial) {
        conn->tlsref.initial = 0;
        xqc_configure_quic(conn);
    }

    SSL * ssl = conn->xc_ssl;
    if (SSL_provide_quic_data(ssl, xqc_convert_xqc_to_ssl_level(encrypt_level), data_pos, data_len) != XQC_SSL_SUCCESS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|SSL_provide_quic_data failed[level:%d]|", encrypt_level);
        return -XQC_TLS_INTERNAL;
    }
    
    if (!xqc_conn_get_handshake_completed(conn)) {
        if (xqc_do_handshake(conn) != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_do_handshake failed |");
            return -XQC_TLS_DO_HANDSHAKE_ERROR;
        }
    } else {
        if (SSL_process_quic_post_handshake(ssl) != XQC_SSL_SUCCESS) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|SSL_process_quic_post_handshake failed |");
            return -XQC_TLS_POST_HANDSHAKE_ERROR;
        }
    }

    return XQC_OK;
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

xqc_int_t 
xqc_tls_recv_initial_cb(xqc_connection_t * conn, xqc_cid_t *dcid)
{
    return xqc_recv_client_hello_derive_key(conn, dcid);
}
