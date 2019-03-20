
#include "xqc_engine.h"
#include "xqc_transport.h"
#include "../include/xquic.h"


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
    config->streams_hash_bucket_size = 127;

    return config;
}

void 
xqc_engine_config_destoy(xqc_config_t *config)
{
    xqc_free(config);
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
    }

    if (engine->log) {
        xqc_free(engine->log);
    }

    if (engine->rand_generator) {
        xqc_random_generator_destroy(engine->rand_generator);
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

