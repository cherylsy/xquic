
#include "xquic.h"
#include "xqc_transport.h"


xqc_connection_t * 
xqc_create_connection(xqc_engine_t *engine, 
                                xqc_cid_t dcid, xqc_cid_t scid,
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

    xc->pool = pool;
    xc->dcid = dcid;
    xc->scid = scid;
    xc->conn_callbacks = *callbacks;
    xc->conn_settings = *settings;
    xc->user_data = user_data;
    xc->version = XQC_QUIC_VERSION;

    xc->streams_hash = xqc_pcalloc(xc->pool, sizeof(xqc_id_hash_table_t));
    if (xc->streams_hash == NULL) {
        goto fail;
    }

    xqc_id_hash_init(&(xc->streams_hash), 
                     xqc_default_allocator,
                     engine->config->streams_hash_bucket_size);

    return xc;

fail:
    if (pool != NULL) {
        xqc_destroy_pool(pool);
    }
    return NULL;
}


xqc_connection_t * 
xqc_client_create_connection(xqc_engine_t *engine, 
                                xqc_cid_t dcid, xqc_cid_t scid,
                                xqc_conn_callbacks_t callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data)
{
    xqc_connection_t *xc = xqc_create_connection(engine, dcid, scid, 
                                        callbacks, settings, user_data, 
                                        XQC_CONN_TYPE_CLIENT);

    if (xc == NULL) {
        return NULL;
    }
                    
    xc->conn_state = XQC_CONN_STATE_CLIENT_INIT;
    xc->cur_stream_id_bidi_local = 0;
    xc->cur_stream_id_uni_local = 2;

    return xc;
}


