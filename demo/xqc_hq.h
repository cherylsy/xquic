#ifndef XQC_HQ_H
#define XQC_HQ_H

#include <xquic/xquic.h>


const xqc_cid_t *
xqc_hq_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);

#endif
