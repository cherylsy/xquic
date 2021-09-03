#include <xquic/xquic.h>
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_client.h"

const xqc_cid_t *
xqc_hq_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    xqc_connection_t *conn;
    conn = xqc_client_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag, 
                              conn_ssl_config, xqc_hq_alpn[conn_settings->proto_version], peer_addr,
                              peer_addrlen, user_data);
    if (conn) {
        return &conn->scid;
    }

    return NULL;
}

