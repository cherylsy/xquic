
#include "xqc_engine.h"
#include "xqc_transport.h"
#include <sys/queue.h>
#include "../include/xquic.h"
#include "../common/xqc_str.h"
#include "../common/xqc_random.h"
#include "../common/xqc_priority_q.h"
#include "../common/xqc_str_hash.h"
#include "../common/xqc_timer.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"


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
    free(hash_table);
    return NULL;
}

void
xqc_engine_conns_hash_destroy(xqc_str_hash_table_t *hash_table)
{
    xqc_str_hash_release(hash_table);
    free(hash_table);
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
    free(q);
    return NULL;
}

void
xqc_engine_conns_pq_destroy(xqc_pq_t *q)
{
    xqc_pq_destroy(q);
    free(q);
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
    
    engine->log = xqc_log_init();
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
xqc_engine_process_conn (xqc_connection_t *conn)
{
    xqc_process_read_streams(conn);
    if (xqc_send_ctl_can_send(conn)) {
        xqc_process_write_streams(conn);
    }
}


/**
 * Process all connections
 */
int
xqc_engine_main_logic (xqc_engine_t *engine)
{
    uint64_t now = xqc_gettimeofday();
    xqc_connection_t *conn;

    while (!xqc_pq_empty(engine->conns_pq)) {
        xqc_conns_pq_elem_t *el = (xqc_conns_pq_elem_t*)xqc_pq_top(engine->conns_pq);
        conn = el->conn;
        xqc_pq_pop(engine->conns_pq);

        xqc_engine_process_conn(conn);

        xqc_conn_send_packets(conn);

    }
    return 0;
}