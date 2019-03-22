
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include "xqc_transport.h"
#include "../include/xquic.h"
#include "../common/xqc_priority_q.h"

typedef struct xqc_conns_pq_elem_s
{
    xqc_pq_key_t        last_process_time_ms;
    xqc_connection_t    *conn;
}xqc_conns_pq_elem_t;

#endif

