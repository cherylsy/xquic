#include <openssl/ssl.h>
#include <openssl/err.h>
#include "xqc_tls_init.h"
#include "xqc_tls_cb.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "transport/xqc_conn.h"
#include "include/xquic_typedef.h"
#include "xqc_tls_0rtt.h"
#include "xqc_tls_if.h"

/*
 * initial ssl config
 *@return 0 means successful
 */

int xqc_ssl_init_engine_config(xqc_engine_t * engine, xqc_engine_ssl_config_t * src, xqc_ssl_session_ticket_key_t * session_ticket_key)
{
    xqc_engine_ssl_config_t *ssl_config = &engine->ssl_config;
    memset(ssl_config, 0, sizeof(xqc_engine_ssl_config_t));

    if(src->private_key_file != NULL && strlen(src->private_key_file) > 0 ){
        int len = strlen(src->private_key_file) + 1;
        ssl_config->private_key_file = (char *)malloc(len);
        strncpy(ssl_config->private_key_file, (const char *)(src->private_key_file), len);
    }else{
        ssl_config->private_key_file = NULL;
    }

    if(src->cert_file != NULL &&  strlen(src->cert_file) > 0 ){
        int len = strlen(src->cert_file) + 1;
        ssl_config->cert_file = (char *)malloc(len);
        strncpy(ssl_config->cert_file, ( char *)(src->cert_file), len);
    }else{
        ssl_config->cert_file = NULL;
    }

    if(src->ciphers != NULL && strlen(src->ciphers) > 0 ){
        int len = strlen(src->ciphers) + 1;
        ssl_config->ciphers = (char *)malloc(len);
        strncpy(ssl_config->ciphers, (const char *)(src->ciphers), len);
    }else{
        ssl_config->ciphers = XQC_TLS_CIPHERS;
    }

    if(src->groups != NULL && strlen(src->groups) > 0 ){
        int len = strlen(src->groups) + 1;
        ssl_config->groups = (char *)malloc(len);
        strncpy(ssl_config->groups, (const char *)(src->groups), len);
    }else{
        ssl_config->groups = XQC_TLS_GROUPS;
    }

    if(src->session_ticket_key_len > 0 ){
        ssl_config->session_ticket_key_len = src->session_ticket_key_len;
        ssl_config->session_ticket_key_data  = (char *)malloc(src->session_ticket_key_len );
        memcpy(ssl_config->session_ticket_key_data, src->session_ticket_key_data, src->session_ticket_key_len);
        if(xqc_init_session_ticket_keys( session_ticket_key, ssl_config->session_ticket_key_data, ssl_config->session_ticket_key_len) < 0){
            //printf("read session ticket key  error\n");
            xqc_log(engine->log, XQC_LOG_ERROR, "|read session ticket key  error|");
            return -1;
        }
    }else{
        ssl_config->session_ticket_key_len = 0;
        ssl_config->session_ticket_key_data = NULL;
        xqc_log(engine->log, XQC_LOG_WARN, "|no session ticket key data|");
        //printf("no session ticket key data\n");
    }
    return 0;
}


int xqc_ssl_init_conn_config(xqc_connection_t * conn, xqc_conn_ssl_config_t * src)
{
    xqc_conn_ssl_config_t * ssl_config = &(conn->tlsref.conn_ssl_config);
    memset(ssl_config, 0, sizeof(xqc_conn_ssl_config_t));
    if(src->session_ticket_len > 0 ){
        ssl_config->session_ticket_len = src->session_ticket_len;
        ssl_config->session_ticket_data  = (char *)xqc_malloc(src->session_ticket_len + 1);
        if(ssl_config->session_ticket_data == NULL){
            xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_malloc error |");
            return -1;
        }
        memcpy(ssl_config->session_ticket_data, src->session_ticket_data, src->session_ticket_len);
        ssl_config->session_ticket_data[src->session_ticket_len] = '\0';
    }else{
        ssl_config->session_ticket_len = 0;
        ssl_config->session_ticket_data = NULL;
        xqc_log(conn->log, XQC_LOG_WARN, "| no session ticket data |");
    }

    if(src->tp_data_len > 0){
        ssl_config->tp_data_len = src->tp_data_len;
        ssl_config->tp_data  = (char *)xqc_malloc(src->tp_data_len + 1 );
        if(ssl_config->tp_data == NULL){
            xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_malloc error | ");
            return -1;
        }
        memcpy(ssl_config->tp_data, src->tp_data, src->tp_data_len);
        ssl_config->tp_data[src->tp_data_len] = '\0';
    }else{
        ssl_config->tp_data_len = 0;
        ssl_config->tp_data = NULL;
        xqc_log(conn->log, XQC_LOG_WARN, "| no no transport parameter data |");
    }

    return 0;
}

int xqc_tlsref_zero(xqc_tlsref_t * tlsref)
{
    memset(tlsref, 0 , sizeof(xqc_tlsref_t));
    return 0;
}

// crypto flag 0 means crypto
//int xqc_client_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, char * hostname, xqc_ssl_config_t *sc, xqc_cid_t *dcid, uint16_t no_crypto_flag ){
int xqc_client_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, char * hostname, xqc_conn_ssl_config_t *sc, xqc_cid_t *dcid, uint16_t no_crypto_flag, uint8_t no_early_data)
{
    xqc_tlsref_t * tlsref = & conn->tlsref;

    xqc_tlsref_zero(tlsref);

    tlsref->conn = conn;
    tlsref->initial = 1;

    if(no_early_data == 0){
        tlsref->no_early_data = 0;
    }else{
        tlsref->no_early_data = 1;
        xqc_log(conn->log, XQC_LOG_WARN, "| no early data set |");
    }

    if( xqc_ssl_init_conn_config(conn, sc) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| initial conn config error |");
        return -1;
    }

    conn->xc_ssl = xqc_create_client_ssl(engine, conn, hostname, sc);// connection ssl config, early data flag should initial before call xqc_create_client_ssl
    if(conn->xc_ssl == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "| xqc_create_client_ssl error |");
        return -1;
    }

    xqc_init_list_head(& conn->tlsref.initial_pktns.msg_cb_head);
    xqc_init_list_head(& conn->tlsref.hs_pktns.msg_cb_head);
    xqc_init_list_head(& conn->tlsref.pktns.msg_cb_head);

    xqc_trans_settings_t * settings = &conn->local_settings;
    if(no_crypto_flag == 1){
        settings->no_crypto = 1;
    }else{
        settings->no_crypto = 0;
    }

    tlsref->aead_overhead = XQC_INITIAL_AEAD_OVERHEAD;

    xqc_tls_callbacks_t * callbacks = & conn->tlsref.callbacks;
    callbacks->client_initial = xqc_client_initial_cb;
    callbacks->recv_client_initial = NULL;
    callbacks->recv_crypto_data = xqc_recv_crypto_data_cb;
    callbacks->handshake_completed = xqc_handshake_completed_cb;
    callbacks->recv_version_negotiation = NULL;
    callbacks->in_encrypt = xqc_do_hs_encrypt;
    callbacks->in_decrypt = xqc_do_hs_decrypt;
    callbacks->encrypt = xqc_do_encrypt;
    callbacks->decrypt = xqc_do_decrypt;
    callbacks->in_hp_mask = do_in_hp_mask;
    callbacks->hp_mask = do_hp_mask;
    callbacks->update_key = xqc_update_key;

    xqc_conn_ssl_config_t *config = &conn->tlsref.conn_ssl_config;
    if( (config->tp_data_len > 0) && (config->tp_data != NULL)){
        xqc_transport_params_t params ;
        memset(&params, 0, sizeof(xqc_transport_params_t));
        if( xqc_read_transport_params(config->tp_data, config->tp_data_len, &params) >= 0){
            int ret = xqc_conn_set_early_remote_transport_params(conn, &params);
            if(ret < 0){
                xqc_log(conn->log, XQC_LOG_DEBUG, "| set early remote transport params failed | error_code:%d |", ret);
            }
        }else{
            xqc_log(conn->log, XQC_LOG_DEBUG, "| read transport params failed |");
        }
    }

    if(xqc_client_setup_initial_crypto_context(conn, dcid) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| error setup initial crypto key |");
        return -1;
    }

    return 0;
}

//int xqc_server_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, xqc_ssl_config_t *sc){
int xqc_server_tls_initial(xqc_engine_t * engine, xqc_connection_t *conn, xqc_engine_ssl_config_t *sc){
    xqc_tlsref_t * tlsref = & conn->tlsref;
    xqc_tlsref_zero(tlsref);

    tlsref->conn = conn;
    tlsref->initial = 1;
    //conn->local_settings.no_crypto = 1;
    conn->xc_ssl = xqc_create_ssl(engine, conn, XQC_SERVER);
    if(conn->xc_ssl == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "|create ssl error|");
        return -1;
    }

    xqc_init_list_head(& conn->tlsref.initial_pktns.msg_cb_head);
    xqc_init_list_head(& conn->tlsref.hs_pktns.msg_cb_head);
    xqc_init_list_head(& conn->tlsref.pktns.msg_cb_head);


    tlsref->aead_overhead = XQC_INITIAL_AEAD_OVERHEAD;

    xqc_tls_callbacks_t * callbacks = & conn->tlsref.callbacks;
    callbacks->client_initial = NULL;
    callbacks->recv_client_initial = xqc_recv_client_initial_cb;
    callbacks->recv_crypto_data = xqc_recv_crypto_data_cb;
    callbacks->handshake_completed = xqc_handshake_completed_cb;
    callbacks->recv_version_negotiation = NULL;
    callbacks->in_encrypt = xqc_do_hs_encrypt;
    callbacks->in_decrypt = xqc_do_hs_decrypt;
    callbacks->encrypt = xqc_do_encrypt;
    callbacks->decrypt = xqc_do_decrypt;
    callbacks->in_hp_mask = do_in_hp_mask;
    callbacks->hp_mask = do_hp_mask;
    callbacks->update_key = xqc_update_key;   //need finish

    return 0;
}

//need finish session save
SSL_CTX *xqc_create_client_ssl_ctx( xqc_engine_t * engine, xqc_engine_ssl_config_t *xs_config)
{
    SSL_CTX * ssl_ctx = SSL_CTX_new(TLS_method());

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION); //todo: get from config file if needed
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    // This makes OpenSSL client not send CCS after an initial
    // ClientHello.
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);


    if (SSL_CTX_set_ciphersuites(ssl_ctx, xs_config->ciphers) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|create ssl error|SSL_CTX_set_ciphersuites:%s|", ERR_error_string(ERR_get_error(), NULL));

        //exit(EXIT_FAILURE);
        return NULL;
    }

    if (SSL_CTX_set1_groups_list(ssl_ctx, xs_config->groups) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        //exit(EXIT_FAILURE);
        return NULL;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_QUIC_HACK);
    //SSL_CTX_set_default_verify_paths(ssl_ctx);

    if (SSL_CTX_add_custom_ext(
                ssl_ctx, XQC_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
                SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                xqc_client_transport_params_add_cb, xqc_transport_params_free_cb, nullptr,
                xqc_client_transport_params_parse_cb, nullptr) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_add_custom_ext| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        //exit(EXIT_FAILURE);
        return NULL;
    }

    SSL_CTX_set_session_cache_mode(
            ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl_ctx, xqc_new_session_cb);
    return ssl_ctx;
}


/*create ssl_ctx for ssl
 *@return SSL_CTX, if error return null
*/
SSL_CTX * xqc_create_server_ssl_ctx(xqc_engine_t * engine, xqc_engine_ssl_config_t *xs_config){

    SSL_CTX * ssl_ctx = SSL_CTX_new(TLS_method());

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    long ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
        SSL_OP_SINGLE_ECDH_USE |
        SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_NO_ANTI_REPLAY;

    SSL_CTX_set_options(ssl_ctx, ssl_opts);
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    if (SSL_CTX_set_ciphersuites(ssl_ctx, xs_config->ciphers) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_set_ciphersuites| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_set1_groups_list(ssl_ctx, xs_config->groups) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_QUIC_HACK);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    SSL_CTX_set_alpn_select_cb(ssl_ctx, xqc_alpn_select_proto_cb, NULL);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, xs_config->private_key_file,
                SSL_FILETYPE_PEM) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, xs_config->cert_file) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_check_private_key| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    if (SSL_CTX_add_custom_ext(
                ssl_ctx, XQC_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
                SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                xqc_server_transport_params_add_cb, xqc_transport_params_free_cb, nullptr,
                xqc_server_transport_params_parse_cb, nullptr) != 1) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|SSL_CTX_check_private_key| error info:%s|", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    SSL_CTX_set_max_early_data(ssl_ctx, XQC_UINT32_MAX);//The max_early_data parameter specifies the maximum amount of early data in bytes that is permitted to be sent on a single connection

    if(xs_config -> session_ticket_key_len == 0 || xs_config -> session_ticket_key_data == NULL){
        xqc_log(engine->log, XQC_LOG_WARN, "| read ssl session ticket key error|");
    }else{
        SSL_CTX_set_tlsext_ticket_key_cb(ssl_ctx, xqc_ssl_session_ticket_key_callback);
    }


    return ssl_ctx;

fail:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

int xqc_bio_write(BIO *b, const char *buf, int len)
{ //never called
    assert(0);
    return -1;
}

int xqc_bio_read(BIO *b, char *buf, int len)
{ //read server handshake data
    BIO_clear_retry_flags(b);

    xqc_connection_t * conn = (xqc_connection_t *) BIO_get_data(b);
    xqc_hs_buffer_t * p_buff = conn->tlsref.hs_to_tls_buf;
    if(p_buff == NULL){
        BIO_set_retry_read(b);
        return -1;
    }
    //int n = xqc_min(p_buff->data_len, len);
    if(p_buff->data_len > len){ //len default value:16K
        //printf("bio buf too small\n");
        return 0;
    }
    memcpy(buf, p_buff->data, p_buff->data_len);
    int ret_len = p_buff->data_len;

    //should free
    free(conn->tlsref.hs_to_tls_buf);
    conn->tlsref.hs_to_tls_buf = NULL;

    if(ret_len == 0){
        BIO_set_retry_read(b);
        return -1;
    }
    return ret_len;
}


int xqc_client_bio_read(BIO *b, char *buf, int len)
{ //read server handshake data
    return xqc_bio_read(b, buf, len);
}

int xqc_server_bio_read(BIO *b, char *buf, int len)
{ // read client handshake data
    return xqc_bio_read(b, buf, len);

}

int xqc_bio_puts(BIO *b, const char *str) { return xqc_bio_write(b, str, strlen(str)); } //just for callback

int xqc_bio_gets(BIO *b, char *buf, int len) { return -1; }//just for callback

long xqc_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{ //just for callback ,do nothing
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
    }

    return 0;
}

int xqc_bio_create(BIO *b)
{  //do creat bio, when handle initialed will be called
    BIO_set_init(b, 1);
    return 1;
}

int xqc_bio_destroy(BIO *b)
{//do nothing
    if (b == nullptr) {
        return 0;
    }

    return 1;
}

BIO_METHOD *xqc_create_bio_method()
{ //just create bio for openssl
    BIO_METHOD * meth = BIO_meth_new(BIO_TYPE_FD, "bio");
    BIO_meth_set_write(meth, xqc_bio_write);
    BIO_meth_set_read(meth, xqc_bio_read);
    BIO_meth_set_puts(meth, xqc_bio_puts);
    BIO_meth_set_gets(meth, xqc_bio_gets);
    BIO_meth_set_ctrl(meth, xqc_bio_ctrl);
    BIO_meth_set_create(meth, xqc_bio_create);
    BIO_meth_set_destroy(meth, xqc_bio_destroy);
    return meth;
}

SSL * xqc_create_ssl(xqc_engine_t * engine, xqc_connection_t * conn , int flag)
{
    SSL *ssl = SSL_new((SSL_CTX *)engine->ssl_ctx);
    if(ssl == NULL){

        xqc_log(conn->log, XQC_LOG_ERROR, "| SSL_new return null | ");
        return NULL;
    }
    BIO * bio = BIO_new(xqc_create_bio_method());
    BIO_set_data(bio, conn);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_app_data(ssl, conn);
    if(flag == XQC_CLIENT){
        SSL_set_connect_state(ssl);
    }else{
        SSL_set_accept_state(ssl);
    }
    SSL_set_msg_callback(ssl, xqc_msg_cb);
    SSL_set_msg_callback_arg(ssl, conn);
    SSL_set_key_callback(ssl, xqc_tls_key_cb, conn);
    return ssl;
}


int xqc_set_alpn_proto(SSL * ssl)
{
    const uint8_t *alpn = nullptr;
    size_t alpnlen;

    alpn = (const uint8_t *)(XQC_ALPN_V1);
    alpnlen = strlen(XQC_ALPN_V1);
    if (alpn) {
        SSL_set_alpn_protos(ssl, alpn, alpnlen);
    }
    return 0;
}

SSL * xqc_create_client_ssl(xqc_engine_t * engine, xqc_connection_t * conn, char * hostname,  xqc_conn_ssl_config_t * sc)
{
    SSL *ssl = xqc_create_ssl(engine, conn, XQC_CLIENT);

    if(ssl == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_create_client_ssl | create ssl error");
        return NULL;
    }

    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    if(xqc_numeric_host(hostname) ){
        SSL_set_tlsext_host_name(ssl, "localhost");  //SNI need finish
    }else{
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    xqc_set_alpn_proto(ssl);

    conn->tlsref.resumption = XQC_FALSE;
    if( conn->tlsref.no_early_data == 0 && sc->session_ticket_data && sc->session_ticket_len > 0 ){
        if(xqc_read_session_data(ssl, conn, sc->session_ticket_data, sc->session_ticket_len) == 0){
            conn->tlsref.resumption = XQC_TRUE;
        }
    }

    return ssl;
}




int xqc_client_setup_initial_crypto_context( xqc_connection_t *conn, xqc_cid_t *dcid )
{
    int rv;

    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN]={0}, secret[INITIAL_SECRET_MAX_LEN]={0};
    rv = xqc_derive_initial_secret(
            initial_secret, sizeof(initial_secret), dcid,
            (const uint8_t *)(XQC_INITIAL_SALT),
            strlen(XQC_INITIAL_SALT));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive initial secret failed | ");
        return -1;
    }

    xqc_prf_sha256(& conn->tlsref.hs_crypto_ctx);
    xqc_aead_aes_128_gcm(& conn->tlsref.hs_crypto_ctx);

    rv = xqc_derive_client_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive client initial secret failed | ");
        return -1;
    }

    char key[16], iv[16], hp[16];

    size_t keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet protection key failed | ");
        return -1;
    }

    size_t ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet protection iv failed | ");
        return -1;
    }

    size_t hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), & conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet header protection key failed | ");
        return -1;
    }
    //need log

    if(xqc_conn_install_initial_tx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| install initial tx  key failed | ");
        return -1;
    }

    rv = xqc_derive_server_initial_secret(secret, sizeof(secret),
            initial_secret,
            sizeof(initial_secret));
    if (rv != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive server initial secret failed | ");
        return -1;
    }

    keylen = xqc_derive_packet_protection_key(
            key, sizeof(key), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (keylen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet protection key failed | ");
        return -1;
    }

    ivlen = xqc_derive_packet_protection_iv(
            iv, sizeof(iv), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (ivlen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet protection iv failed | ");
        return -1;
    }

    hplen = xqc_derive_header_protection_key(
            hp, sizeof(hp), secret, sizeof(secret), &conn->tlsref.hs_crypto_ctx);
    if (hplen < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "| derive packet header protection key failed | ");
        return -1;
    }

    if(xqc_conn_install_initial_rx_keys(conn, key, keylen, iv, ivlen, hp, hplen) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "| install initial key error | ");
        return -1;
    }

    return 0;
}



