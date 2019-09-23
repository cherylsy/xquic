
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
    h3_conn->h3_conn_callbacks = conn->engine->eng_callback.h3_conn_callbacks;

#ifdef XQC_HTTP3_PRIORITY_ENABLE
    if(xqc_tnode_hash_create(&h3_conn->tnode_hash, XQC_TNODE_HASH_SIZE) < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|create tnode hash table failed|");
        goto final;
    }

    xqc_http3_tnode_t nid;
    xqc_http3_node_id_init(&nid, XQC_HTTP3_NODE_ID_TYPE_ROOT, 0);
    h3_conn->tnode_root = xqc_http3_create_tnode(&h3_conn->tnode_hash, &nid, 0, XQC_HTTP3_DEFAULT_WEIGHT, NULL );
    if(h3_conn->tnode_root == NULL){
        xqc_log(conn->log, XQC_LOG_ERROR, "|create tnode root failed|");
        goto final;
    }
#endif

    if (h3_conn->h3_conn_callbacks.h3_conn_create_notify) {
        if (h3_conn->h3_conn_callbacks.h3_conn_create_notify(h3_conn, user_data)) {
            goto fail;
        }
        h3_conn->flags |= XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST;
    }

    return h3_conn;
fail:
    xqc_h3_conn_destroy(h3_conn);
    return NULL;
}

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn->h3_conn_callbacks.h3_conn_close_notify && (h3_conn->flags & XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST)) {
        h3_conn->h3_conn_callbacks.h3_conn_close_notify(h3_conn, h3_conn->user_data);
        h3_conn->flags &= ~XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST;
    }

#ifdef XQC_HTTP3_PRIORITY_ENABLE
    xqc_tnode_free_hash_table(&h3_conn->tnode_hash);
#endif

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    xqc_free(h3_conn);
}

int
xqc_h3_conn_close(xqc_h3_conn_t *h3_conn)
{
    return xqc_conn_close(h3_conn->conn->engine, &h3_conn->conn->scid);
}

int
xqc_h3_conn_send_goaway(xqc_h3_conn_t *h3_conn)
{
    ssize_t ret;
    unsigned char *data;
    size_t data_len;
    //gen_goaway_frame
    h3_conn->goaway_stream_id = h3_conn->max_stream_id_recvd + 4;
    ret = xqc_h3_stream_send(h3_conn->control_stream_out, data, data_len, 0);
    if (ret < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_send_data error|");
        return ret;
    }
    h3_conn->flags |= XQC_HTTP3_CONN_FLAG_GOAWAY_SEND;
    return XQC_OK;
}

int
xqc_h3_conn_goaway_recvd(xqc_h3_conn_t *h3_conn, xqc_stream_id_t goaway_stream_id)
{
    h3_conn->goaway_stream_id = goaway_stream_id;
    h3_conn->flags |= XQC_HTTP3_CONN_FLAG_GOAWAY_RECVD;
    return XQC_OK;
}

int
xqc_h3_conn_send_settings(xqc_h3_conn_t *h3_conn)
{
    int ret;

    xqc_http3_conn_settings settings;
    ret = xqc_http3_stream_write_settings(h3_conn->control_stream_out, &settings);
    if (ret < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_stream_write_settings error|");
        return ret;
    }
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}

int
xqc_h3_conn_setting_recvd(xqc_h3_conn_t *h3_conn)
{
    return XQC_OK;
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

    //send SETTINGS
    ret = xqc_h3_conn_send_settings(h3_conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_send_settings error|");
        return ret;
    }
    return XQC_OK;
}

int
xqc_h3_conn_close_notify(xqc_connection_t *conn, void *user_data)
{
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)user_data;
    xqc_h3_conn_destroy(h3_conn);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|destroy h3 conn success|");
    return XQC_OK;
}

const xqc_conn_callbacks_t conn_callbacks = {
        .conn_create_notify = xqc_h3_conn_create_notify,
        .conn_close_notify = xqc_h3_conn_close_notify,
};
