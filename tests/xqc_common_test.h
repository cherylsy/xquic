#ifndef xqc_common_test_h
#define xqc_common_test_h

#include "common/xqc_queue.h"
#include "common/xqc_hash.h"
#include "include/xquic.h"
#include "common/xqc_log.h"

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

static inline xqc_engine_t* test_create_engine()
{
    def_engine_ssl_config;
    xqc_engine_callback_t callback = {
            .log_callbacks = null_log_cb,
    };

    xqc_conn_settings_t conn_settings;
    return xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, conn_settings, NULL);
}

#endif
