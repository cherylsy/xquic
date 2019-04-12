
#include "../include/xquic.h"
#include "../common/xqc_common.h"
#include "../common/xqc_malloc.h"
#include "../common/xqc_str_hash.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "../common/xqc_priority_q.h"
#include "xqc_engine.h"
#include "xqc_cid.h"
#include "xqc_stream.h"
#include "../common/xqc_hash.h"

int
xqc_conns_pq_push (xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_ms)
{
    xqc_conns_pq_elem_t *elem = (xqc_conns_pq_elem_t*)xqc_pq_push(pq, time_ms);
    if (!elem) {
        return -1;
    }
    elem->conn = conn;
    return 0;
}

void
xqc_conns_pq_pop (xqc_pq_t *pq)
{
    xqc_pq_pop(pq);
}

xqc_conns_pq_elem_t *
xqc_conns_pq_top (xqc_pq_t *pq)
{
    return  (xqc_conns_pq_elem_t*)xqc_pq_top(pq);
}


static inline int
xqc_insert_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn)
{
    xqc_cid_t *dcid = &conn->dcid;

    uint64_t hash = xqc_hash_string(dcid->cid_buf, dcid->cid_len);

    xqc_str_hash_element_t c = {
            .str    = {
                        .data = dcid->cid_buf,
                        .len = dcid->cid_len
                    },
            .hash   = hash,
            .value  = conn
    };
    if (xqc_str_hash_add(conns_hash, c)) {
        return -1;
    }
    return 0;
}

static inline int
xqc_remove_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn)
{
    xqc_cid_t *dcid = &conn->dcid;
    uint64_t hash = xqc_hash_string(dcid->cid_buf, dcid->cid_len);
    xqc_str_t str = {
        .data   = dcid->cid_buf,
        .len    = dcid->cid_len,
    };
    if (xqc_str_hash_delete(conns_hash, hash, str)) {
        return -1;
    }
    return 0;
}

xqc_connection_t *
xqc_create_connection(xqc_engine_t *engine,
                                xqc_cid_t *dcid, xqc_cid_t *scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data,
                                xqc_conn_type_t type)
{
    xqc_connection_t *xc = NULL;
    xqc_memory_pool_t *pool = xqc_create_pool(engine->config->conn_pool_size);

    if (pool == NULL) {
        return NULL;
    }

    xc = xqc_pcalloc(pool, sizeof(xqc_connection_t));
    if (xc == NULL) {
        goto fail;
    }

    xc->conn_pool = pool;
    xqc_cid_copy(&(xc->dcid), dcid);
    xqc_cid_copy(&(xc->scid), scid);
    xc->engine = engine;
    xc->log = engine->log;
    xc->conn_callbacks = *callbacks;
    xc->conn_settings = *settings;
    xc->user_data = user_data;
    xc->version = XQC_QUIC_VERSION;
    xc->discard_vn_flag = 0;
    xc->conn_type = type;
    xc->conn_flag = XQC_CONN_FLAG_NONE;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xc->zero_rtt_count = 0;

    xc->conn_send_ctl = xqc_send_ctl_create(xc);
    if (xc->conn_send_ctl == NULL) {
        goto fail;
    }

    TAILQ_INIT(&xc->conn_write_streams);
    TAILQ_INIT(&xc->conn_read_streams);
    TAILQ_INIT(&xc->packet_in_tailq);

    /* create streams_hash */
    xc->streams_hash = xqc_pcalloc(xc->conn_pool, sizeof(xqc_id_hash_table_t));
    if (xc->streams_hash == NULL) {
        goto fail;
    }
    if (xqc_id_hash_init(xc->streams_hash,
                         xqc_default_allocator,
                         engine->config->streams_hash_bucket_size) == XQC_ERROR) {
        goto fail;
    }

    /* Insert into engine's conns_hash */
    if (xqc_insert_conns_hash(engine->conns_hash, xc)) {
        goto fail;
    }

    if (xqc_conns_pq_push(engine->conns_pq, xc, 0)) {
        goto fail;
    }
    xc->conn_flag |= XQC_CONN_FALG_TICKING;

    /* Do callback */
    if (xc->conn_callbacks.conn_create_notify(user_data, xc)) {
        goto fail;
    }



    return xc;

fail:
    if (pool != NULL) {
        xqc_destroy_pool(pool);
    }
    return NULL;
}


void
xqc_destroy_connection(xqc_connection_t *xc)
{
    if (!xc) {
        return;
    }
    /* free streams hash */
    if (xc->streams_hash) {
        xqc_id_hash_release(xc->streams_hash);
        xc->streams_hash = NULL;
    }

    /* free pool */
    if (xc->conn_pool) {
        xqc_destroy_pool(xc->conn_pool);
        xc->conn_pool = NULL;
    }

    /* Remove from engine's conns_hash */
    if (xc->engine->conns_hash) {
        xqc_remove_conns_hash(xc->engine->conns_hash, xc);
        xc->engine->conns_hash = NULL;
    }
}


xqc_connection_t * 
xqc_client_create_connection(xqc_engine_t *engine, 
                                xqc_cid_t dcid, xqc_cid_t scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data)
{
    xqc_connection_t *xc = xqc_create_connection(engine, &dcid, &scid, 
                                        callbacks, settings, user_data, 
                                        XQC_CONN_TYPE_CLIENT);

    if (xc == NULL) {
        return NULL;
    }
                    
    xc->cur_stream_id_bidi_local = 0;
    xc->cur_stream_id_uni_local = 2;

    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, user_data);
    if (!xc->crypto_stream[XQC_ENC_LEV_INIT]) {
        goto fail;
    }
    return xc;

fail:
    xqc_destroy_connection(xc);
    return NULL;
}

void
xqc_conn_send_packets (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &conn->conn_send_ctl->ctl_packets, po_next) {
        if (xqc_send_ctl_can_send(conn) && !XQC_PKTOUT_SENT(packet_out)) {
            conn->engine->eng_callback.write_socket(conn, packet_out->po_buf, packet_out->po_used_size);
            XQC_PKTOUT_SET_SENT(packet_out);
        }
    }
    //TODO: del packet_out
}


xqc_int_t
xqc_conn_check_handshake_completed(xqc_connection_t *conn)
{
    return ((conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) != 0);
}

