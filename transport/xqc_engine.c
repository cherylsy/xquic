
#include "xqc_engine.h"
#include "xqc_transport.h"
#include "../include/xquic.h"


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
        return NULL;
    }
    xqc_memzero(engine, sizeof(xqc_engine_t));

    engine->config = xqc_malloc(sizeof(xqc_config_t));
    if (engine->config == NULL) {
        goto fail;
    }
    xqc_memzero(engine->config, sizeof(xqc_config_t));

    engine->log = xqc_log_init();
    if (engine->log == NULL) {
        goto fail;
    }
    
    engine->eng_type = engine_type;

    return engine;

fail:
    if (engine->config) {
        xqc_free(engine->config);
    }
    if (engine->log) {
        xqc_free(engine->log);
    }
    xqc_free(engine);
    return NULL;
}


void 
xqc_engine_destroy(xqc_engine_t *engine)
{
    if (engine == NULL) {
        return;
    }
    xqc_free(engine->log);
    xqc_free(engine->config);
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

