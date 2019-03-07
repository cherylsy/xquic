#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#define XQC_TRANSPORT_VERSION "1.0"

#include "xqc_transport.h"
#include "../common/xqc_memory_pool.h"

typedef struct {

}xqc_conn_callbacks_t;

typedef struct {
    uint64_t cid;
}xqc_cid_t;

typedef enum {
    /* server */
    XQC_CONN_SERVER_STATE_INIT,
    XQC_CONN_SERVER_STATE_INITIAL_RECVD,
    XQC_CONN_SERVER_STATE_INITIAL_SENT,
    XQC_CONN_SERVER_STATE_HANDSHAKE_SENT,
    XQC_CONN_SERVER_STATE_HANDSHAKE_RECVD,
    /* client & server */
    XQC_CONN_STATE_ESTABED,
    XQC_CONN_STATE_CLOSING,
    XQC_CONN_STATE_DRAINING,
    XQC_CONN_STATE_CLOSED
}xqc_conn_state_t;

typedef struct {
    xqc_conn_callbacks_t conn_callbacks;
    xqc_cid_t dcid;
    xqc_cid_t scid;
   
    xqc_conn_state_t conn_state;
    xqc_memory_pool_t *pool;

    /* recovery state ctx */

    /* congestion control ctx */
    /* flag */
}xqc_connection_t;

#endif /* _XQC_CONN_H_INCLUDED_ */
