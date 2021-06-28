#ifndef xqc_common_test_h
#define xqc_common_test_h

#include "src/common/xqc_queue.h"
#include "src/common/xqc_hash.h"
#include "xquic/xquic.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"

void xqc_test_common();

#define def_engine_ssl_config   \
xqc_engine_ssl_config_t  engine_ssl_config;             \
engine_ssl_config.private_key_file = "./server.key";    \
engine_ssl_config.cert_file = "./server.crt";           \
engine_ssl_config.ciphers = XQC_TLS_CIPHERS;            \
engine_ssl_config.groups = XQC_TLS_GROUPS;              \
engine_ssl_config.session_ticket_key_len = 0;           \
engine_ssl_config.session_ticket_key_data = NULL;       \
engine_ssl_config.alpn_list_len = 0;                    \
engine_ssl_config.alpn_list = NULL;

static inline ssize_t null_socket_write(const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen, void *conn_user_data)
{
    return size;
}

static inline void null_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

static inline xqc_engine_t* test_create_engine()
{
    def_engine_ssl_config;
    xqc_engine_callback_t callback = {
            .log_callbacks = xqc_null_log_cb,
            .write_socket = null_socket_write,
            .set_event_timer = null_set_event_timer,
    };

    xqc_conn_settings_t conn_settings;
    return xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, &callback, NULL);
}

static inline xqc_cid_t* test_cid_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_IDRAFT_VER_29;
    
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0 ,sizeof(conn_ssl_config));
    xqc_cid_t *cid = xqc_connect(engine, NULL, &conn_settings, NULL, 0, "", 0, &conn_ssl_config, NULL, 0);
    return cid;
}

static inline xqc_connection_t* test_connect(xqc_engine_t *engine)
{
    xqc_cid_t *cid = test_cid_connect(engine);
    if (cid == NULL) {
        return NULL;
    }
    return xqc_engine_conns_hash_find(engine, cid, 's');
}

static inline xqc_connection_t* test_engine_connect()
{
    xqc_engine_t *engine = test_create_engine();
    if (engine == NULL) {
        return NULL;
    }
    xqc_connection_t *conn = test_connect(engine);
    return conn;
}

#endif
