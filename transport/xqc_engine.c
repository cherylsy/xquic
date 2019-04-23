
#include "xqc_engine.h"
#include "xqc_transport.h"
#include <sys/queue.h>
#include "../include/xquic.h"
#include "../common/xqc_str.h"
#include "../common/xqc_random.h"
#include "../common/xqc_priority_q.h"
#include "../common/xqc_str_hash.h"
#include "../common/xqc_timer.h"
#include "../common/xqc_hash.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_packet_in.h"
#include "xqc_packet.h"
#include "xqc_cid.h"


xqc_config_t *
xqc_engine_config_create(xqc_engine_type_t engine_type)
{
    xqc_config_t *config = xqc_malloc(sizeof(xqc_config_t));
    if (config == NULL) {
        return NULL;
    }

    xqc_memzero(config, sizeof(xqc_config_t));

    /* set default value */
    config->conn_pool_size = 4096;

    if (engine_type == XQC_ENGINE_SERVER) {
        config->streams_hash_bucket_size = 127;
        config->conns_hash_bucket_size = 127;
        config->conns_pq_capacity = 127;
    } else if (engine_type == XQC_ENGINE_CLIENT) { //TODO: confirm the value
        config->streams_hash_bucket_size = 8;
        config->conns_hash_bucket_size = 8;
        config->conns_pq_capacity = 8;
    }

    config->support_version_count = 1;
    config->support_version_list[0] = XQC_QUIC_VERSION;

    return config;
}

void 
xqc_engine_config_destoy(xqc_config_t *config)
{
    xqc_free(config);
}

xqc_str_hash_table_t *
xqc_engine_conns_hash_create(xqc_config_t *config)
{
    xqc_str_hash_table_t *hash_table = xqc_malloc(sizeof(xqc_str_hash_table_t));
    if (hash_table == NULL) {
        return NULL;
    }

    if (xqc_str_hash_init(hash_table, xqc_default_allocator, config->conns_hash_bucket_size)) {
        goto fail;
    }

    return hash_table;

fail:
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
    return NULL;
}

void
xqc_engine_conns_hash_destroy(xqc_str_hash_table_t *hash_table)
{
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
}

xqc_pq_t *
xqc_engine_conns_pq_create(xqc_config_t *config)
{
    xqc_pq_t *q = xqc_malloc(sizeof(xqc_pq_t));
    if (q == NULL) {
        return NULL;
    }

    xqc_memzero(q, sizeof(xqc_pq_t));

    if (xqc_pq_init(q, sizeof(xqc_conns_pq_elem_t), config->conns_pq_capacity,
                    xqc_default_allocator, xqc_pq_revert_cmp)) {
        goto fail;
    }

    return q;

fail:
    xqc_pq_destroy(q);
    xqc_free(q);
    return NULL;
}


xqc_int_t
xqc_engine_conns_hash_insert(xqc_engine_t *engine, xqc_connection_t *c)
{
    xqc_str_hash_element_t element;
    element.hash = xqc_hash_string(c->dcid.cid_buf, c->dcid.cid_len);
    element.str.data = c->dcid.cid_buf;
    element.str.len = c->dcid.cid_len;
    element.value = c;

    return xqc_str_hash_add(engine->conns_hash, element);
}


xqc_connection_t *
xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *dcid)
{
    if (dcid == NULL || dcid->cid_len == 0 || dcid->cid_buf == NULL) {
        return NULL;
    }

    uint64_t hash = xqc_hash_string(dcid->cid_buf, dcid->cid_len);
    xqc_str_t str;
    str.data = dcid->cid_buf;
    str.len = dcid->cid_len;

    return xqc_str_hash_find(engine->conns_hash, hash, str);
}


void
xqc_engine_conns_pq_destroy(xqc_pq_t *q)
{
    xqc_pq_destroy(q);
    xqc_free(q);
}

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *
xqc_engine_create(xqc_engine_type_t engine_type)
{
    xqc_engine_t *engine = NULL;

    engine = xqc_malloc(sizeof(xqc_engine_t));
    if (engine == NULL) {
        goto fail;
    }
    xqc_memzero(engine, sizeof(xqc_engine_t));

    engine->eng_type = engine_type;

    engine->config = xqc_engine_config_create(engine_type);
    if (engine->config == NULL) {
        goto fail;
    }
    
    engine->log = xqc_log_init(XQC_LOG_DEBUG, "./", "log");
    if (engine->log == NULL) {
        goto fail;
    }
    
    engine->rand_generator = xqc_random_generator_create(engine->log);
    if (engine->rand_generator == NULL) {
        goto fail;
    }

    engine->conns_hash = xqc_engine_conns_hash_create(engine->config);
    if (engine->conns_hash == NULL) {
        goto fail;
    }

    engine->conns_pq = xqc_engine_conns_pq_create(engine->config);
    if (engine->conns_pq == NULL) {
        goto fail;
    }

    engine->conns_wakeup_pq = xqc_engine_conns_pq_create(engine->config);
    if (engine->conns_wakeup_pq == NULL) {
        goto fail;
    }

    return engine;

fail:
    xqc_engine_destroy(engine);
    return NULL;
}


void 
xqc_engine_destroy(xqc_engine_t *engine)
{
    if (engine == NULL) {
        return;
    }

    if (engine->config) {
        xqc_engine_config_destoy(engine->config);
        engine->config = NULL;
    }

    if (engine->log) {
        xqc_free(engine->log);
        engine->log = NULL;
    }

    if (engine->rand_generator) {
        xqc_random_generator_destroy(engine->rand_generator);
        engine->rand_generator = NULL;
    }

    if (engine->conns_hash) {
        xqc_engine_conns_hash_destroy(engine->conns_hash);
        engine->conns_hash = NULL;
    }
    if (engine->conns_pq) {
        xqc_engine_conns_pq_destroy(engine->conns_pq);
        engine->conns_pq = NULL;
    }
    if (engine->conns_wakeup_pq) {
        xqc_engine_conns_pq_destroy(engine->conns_wakeup_pq);
        engine->conns_wakeup_pq = NULL;
    }
    xqc_free(engine);
}


/**
 * Init engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
void 
xqc_engine_init_config (xqc_engine_t *engine,
                             xqc_config_t *engine_config, 
                             xqc_engine_type_t engine_type)
{
    *(engine->config) = *engine_config;
}

void
xqc_engine_set_callback (xqc_engine_t *engine,
                              xqc_engine_callback_t engine_callback)
{
    engine->eng_callback = engine_callback;
}

void
xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now)
{
    xqc_send_ctl_timer_expire(conn->conn_send_ctl, now);

    if (conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) {
        xqc_process_read_streams(conn);
        if (xqc_send_ctl_can_send(conn)) {
            xqc_process_write_streams(conn);
        }
    }
    else {
        xqc_process_crypto_read_streams(conn);
        xqc_process_crypto_write_streams(conn);
    }

    if (xqc_should_generate_ack(conn)) {
        xqc_write_ack_to_packets(conn);
    }
}


/**
 * Process all connections
 */
int
xqc_engine_main_logic (xqc_engine_t *engine)
{
    xqc_msec_t now = xqc_gettimeofday();
    xqc_connection_t *conn;

    while (!xqc_pq_empty(engine->conns_pq)) {
        xqc_conns_pq_elem_t *el = xqc_conns_pq_top(engine->conns_pq);
        conn = el->conn;
        xqc_conns_pq_pop(engine->conns_pq);
        conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;

        xqc_engine_process_conn(conn, now);

        xqc_conn_retransmit_lost_packets(conn);
        xqc_conn_send_packets(conn);

    }
    return 0;
}


/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in millisecond
 */
xqc_int_t xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time)
{
    /* find connection with cid*/
    xqc_connection_t *conn = NULL;
    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    if (xqc_packet_parse_cid(&dcid, &scid, (unsigned char *)packet_in_buf, packet_in_size) != XQC_OK) {
        xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to parse cid");
        return XQC_ERROR;
    }

    conn = xqc_engine_conns_hash_find(engine, &dcid);

    /* client need user_data, do not auto create */
    if (conn == NULL && engine->eng_type != XQC_ENGINE_CLIENT) {
        xqc_conn_type_t conn_type = (engine->eng_type == XQC_ENGINE_SERVER) ?
                                     XQC_CONN_TYPE_SERVER : XQC_CONN_TYPE_CLIENT;

        conn = xqc_create_connection(engine, &dcid, &scid, 
                                     &(engine->eng_callback.conn_callbacks), 
                                     engine->settings, NULL, 
                                     conn_type);

        if (conn == NULL) {
            xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to create connection");
            return XQC_ERROR;
        }

        if (xqc_engine_conns_hash_insert(engine, conn) != XQC_OK) {
            xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to insert conns hash");
            return XQC_ERROR;
        }
    }
    if (conn == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to find connection");
        return XQC_ERROR;
    }

    /* create packet in */
    xqc_packet_in_t *packet_in = xqc_create_packet_in(conn->conn_pool,
                                                      &conn->packet_in_tailq,
                                                      packet_in_buf, packet_in_size, 
                                                      recv_time); //TODO: when to del
    if (!packet_in) {
        xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to create packet in");
        return XQC_ERROR;
    }

    /* process packets */    
    if (xqc_conn_process_packets(conn, packet_in) != XQC_OK) {
        return XQC_ERROR;
    }

#if 1
    /* main logic */
    if (xqc_engine_main_logic(engine) != XQC_OK) {
        return XQC_ERROR;
    }
#endif
    return XQC_OK;
}
