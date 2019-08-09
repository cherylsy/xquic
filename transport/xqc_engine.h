
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_priority_q.h"

/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);

void xqc_engine_config_destroy(xqc_config_t *config);

void xqc_engine_set_callback (xqc_engine_t *engine,
                         xqc_engine_callback_t engine_callback);

/**
 * @return >0 : user should call xqc_engine_main_logic after N ms
 */
xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

xqc_connection_t * xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *cid, char type);

void xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now);

#endif

