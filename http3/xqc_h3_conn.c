
#include "transport/xqc_conn.h"
#include "transport/xqc_client.h"
#include "xqc_h3_conn.h"
#include "include/xquic.h"
#include "xqc_h3_stream.h"
#include "common/xqc_errno.h"

xqc_cid_t *
xqc_h3_connect(xqc_engine_t *engine, void *user_data,
               unsigned char *token, unsigned token_len,
               char *server_host, int no_crypto_flag,
               uint8_t no_early_data_flag,
               xqc_conn_ssl_config_t *conn_ssl_config)
{
    xqc_connection_t *conn;
    conn = xqc_client_connect(engine, user_data, token, token_len, server_host,
            no_crypto_flag, no_early_data_flag, conn_ssl_config);
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_client_connect error|");
        return NULL;
    }

    return &conn->scid;
}

xqc_h3_conn_t *
xqc_h3_conn_create(xqc_connection_t *conn, void *user_data)
{
    xqc_h3_conn_t *h3_conn;
    h3_conn = xqc_calloc(1, sizeof(xqc_h3_conn_t));
    if (!h3_conn) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3_conn->conn = conn;
    h3_conn->log = conn->log;
    h3_conn->user_data = user_data;

    conn->conn_flag |= XQC_CONN_FLAG_HAS_H3;

    return h3_conn;
}

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn)
{
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|done|");
    xqc_free(h3_conn);
}

int
xqc_h3_conn_create_notify(xqc_connection_t *conn, void *user_data)
{
    int ret;
    xqc_h3_conn_t *h3_conn;
    h3_conn = xqc_h3_conn_create(conn, user_data);
    if (!h3_conn) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_create error|");
        return -XQC_H3_EMALLOC;
    }

    /* 替换为h3的上下文 */
    conn->user_data = h3_conn;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|create h3 conn success|");

    ret = xqc_h3_stream_create_control(h3_conn, NULL);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_create_control error|");
        return ret;
    }

    //TODO: send SETTINGS
    return XQC_OK;
}

int
xqc_h3_conn_close_notify(xqc_connection_t *conn, void *user_data)
{
    if (!(conn->conn_flag & XQC_CONN_FLAG_HAS_H3)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|has no h3 conn|");
        return XQC_OK;
    }
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)user_data;
    xqc_h3_conn_destroy(h3_conn);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|destroy h3 conn success|");
    return XQC_OK;
}

const xqc_conn_callbacks_t conn_callbacks = {
        .conn_create_notify = xqc_h3_conn_create_notify,
        .conn_close_notify = xqc_h3_conn_close_notify,
};