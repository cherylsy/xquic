
#include <xquic/xquic.h>
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_client.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"

xqc_cid_t *
xqc_h3_connect(xqc_engine_t *engine, void *user_data,
               xqc_conn_settings_t conn_settings,
               unsigned char *token, unsigned token_len,
               char *server_host, int no_crypto_flag,
               xqc_conn_ssl_config_t *conn_ssl_config,
               const struct sockaddr *peer_addr,
               socklen_t peer_addrlen)
{
    conn_ssl_config->alpn = XQC_ALPN_HTTP3;
    xqc_connection_t *conn;
    conn = xqc_client_connect(engine, user_data, conn_settings, token, token_len, server_host,
            no_crypto_flag, conn_ssl_config, peer_addr, peer_addrlen);
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_client_connect error|");
        return NULL;
    }

    return &conn->scid;
}

void
xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3_conn,
                          void *user_data)
{
    h3_conn->user_data = user_data;
}


struct sockaddr*
xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3_conn,
                          socklen_t *peer_addr_len)
{
    return xqc_conn_get_peer_addr(h3_conn->conn, peer_addr_len);
}

struct sockaddr *
xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3_conn,
                           socklen_t *local_addr_len)
{
    return xqc_conn_get_peer_addr(h3_conn->conn, local_addr_len);
}

int
xqc_h3_conn_close(xqc_engine_t *engine, xqc_cid_t *cid)
{
    return xqc_conn_close(engine, cid);
}

xqc_connection_t *  
xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3_conn)
{
    return  XQC_LIKELY(h3_conn) ? h3_conn->conn : NULL ;
}

int 
xqc_h3_conn_get_errno(xqc_h3_conn_t *h3_conn)
{
    int ret = xqc_conn_get_errno(h3_conn->conn);
    return ret == 0 ? HTTP_NO_ERROR : ret;
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

    h3_conn->control_stream_in = NULL;
    h3_conn->control_stream_out = NULL;

    h3_conn->h3_conn_callbacks = conn->engine->eng_callback.h3_conn_callbacks;

    xqc_h3_qpack_encoder_init(&h3_conn->qenc, 
                        QPACK_MAX_TABLE_CAPACITY, DEFAULT_MAX_DTABLE_SIZE, 
                        DEFAULT_QPACK_BLOCK_STREAM, DEFAULT_QPACK_HASH_TABLE_SIZE, h3_conn);
    xqc_h3_qpack_decoder_init(&h3_conn->qdec, 
                        QPACK_MAX_TABLE_CAPACITY, DEFAULT_MAX_DTABLE_SIZE, 
                        DEFAULT_QPACK_BLOCK_STREAM, h3_conn);

    xqc_init_list_head(&h3_conn->block_stream_head);
    h3_conn->qdec_stream = NULL;
    h3_conn->qenc_stream = NULL;

    if (h3_conn->h3_conn_callbacks.h3_conn_create_notify) {
        if (h3_conn->h3_conn_callbacks.h3_conn_create_notify(h3_conn, &h3_conn->conn->scid, user_data)) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|h3_conn_create_notify failed|");
            goto fail;
        }
        h3_conn->flags |= XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST;
    }

    /* replace with h3_conn */
    conn->user_data = h3_conn;

    return h3_conn;
fail:
    xqc_h3_conn_destroy(h3_conn);
    return NULL;
}

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn->h3_conn_callbacks.h3_conn_close_notify && (h3_conn->flags & XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST)) {
        h3_conn->h3_conn_callbacks.h3_conn_close_notify(h3_conn, &h3_conn->conn->scid, h3_conn->user_data);
        h3_conn->flags &= ~XQC_HTTP3_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_http3_qpack_decoder_free(&h3_conn->qdec);
    xqc_http3_qpack_encoder_free(&h3_conn->qenc);

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    xqc_free(h3_conn);
}

int 
xqc_h3_conn_send_ping(xqc_engine_t *engine, xqc_cid_t *cid, void *user_data)
{
    return xqc_conn_send_ping(engine, cid, user_data);
}

int
xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn->conn->tlsref.resumption) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

int
xqc_h3_conn_send_goaway(xqc_h3_conn_t *h3_conn)
{
    ssize_t ret;
    unsigned char *data = NULL;
    size_t data_len = 0;
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

    memset(&settings, 0, sizeof(settings));
    ret = xqc_http3_stream_write_settings(h3_conn->control_stream_out, &settings);
    if (ret < 0) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_http3_stream_write_settings error|");
        return ret;
    }
    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    return XQC_OK;
}

int
xqc_h3_conn_setting_recvd(xqc_h3_conn_t *h3_conn)//TODO
{
    return XQC_OK;
}

int
xqc_h3_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    int ret;
    xqc_h3_conn_t *h3_conn;
    h3_conn = xqc_h3_conn_create(conn, user_data);
    if (!h3_conn) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_create error|");
        return -XQC_H3_ECREATE_CONN;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|create h3 conn success|");

    ret = xqc_h3_stream_create_control_stream(h3_conn, NULL);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_create_control_stream error|");
        return ret;
    }

    ret = xqc_h3_stream_create_qpack_stream(h3_conn, NULL, XQC_HTTP3_STREAM_TYPE_QPACK_ENCODER);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_create_qpack_encoder error|");
        return ret;
    }

    ret = xqc_h3_stream_create_qpack_stream(h3_conn, NULL, XQC_HTTP3_STREAM_TYPE_QPACK_DECODER);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_stream_create_qpack_encoder error|");
        return ret;
    }

    /* send SETTINGS */
    ret = xqc_h3_conn_send_settings(h3_conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_send_settings error|");
        return ret;
    }
    return XQC_OK;
}

int
xqc_h3_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)user_data;
    xqc_h3_conn_destroy(h3_conn);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|destroy h3 conn success|");
    return XQC_OK;
}

void
xqc_h3_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)user_data;
    if (h3_conn->h3_conn_callbacks.h3_conn_handshake_finished) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|HANDSHAKE_COMPLETED notify|");
        h3_conn->h3_conn_callbacks.h3_conn_handshake_finished(h3_conn, h3_conn->user_data);
    }
}

void
xqc_h3_conn_ping_acked_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data, void *ping_user_data)
{
    xqc_h3_conn_t *h3_conn = (xqc_h3_conn_t*)user_data;
    if (h3_conn->h3_conn_callbacks.h3_conn_ping_acked) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|Ping acked notify|");
        h3_conn->h3_conn_callbacks.h3_conn_ping_acked(h3_conn, &h3_conn->conn->scid, h3_conn->user_data, ping_user_data);
    }
    return;
}

const xqc_conn_callbacks_t h3_conn_callbacks = {
        .conn_create_notify = xqc_h3_conn_create_notify,
        .conn_close_notify = xqc_h3_conn_close_notify,
        .conn_handshake_finished = xqc_h3_conn_handshake_finished,
        .conn_ping_acked = xqc_h3_conn_ping_acked_notify,
};
