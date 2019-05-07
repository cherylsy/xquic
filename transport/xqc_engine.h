
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_priority_q.h"

typedef struct xqc_conns_pq_elem_s
{
    xqc_pq_key_t        time_ms;
    xqc_connection_t    *conn;
}xqc_conns_pq_elem_t;

xqc_connection_t * xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *dcid);

#endif

