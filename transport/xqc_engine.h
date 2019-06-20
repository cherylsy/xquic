
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

typedef struct xqc_conns_pq_elem_s
{
    xqc_pq_key_t        time_ms;
    xqc_connection_t    *conn;
}xqc_conns_pq_elem_t;

xqc_connection_t * xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *cid, char type);

#endif

