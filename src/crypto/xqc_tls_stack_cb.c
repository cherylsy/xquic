#include "src/crypto/xqc_tls_stack_cb.h"
#include "src/transport/xqc_conn.h"


xqc_bool_t 
xqc_conn_get_handshake_completed(xqc_connection_t *conn) {
   return (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX) &&
        (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED);
}

static xqc_int_t 
xqc_conn_handshake_completed_handled(xqc_connection_t *conn)
{
    int rv = 0;

    conn->tlsref.flags |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED;

    if(conn->tlsref.callbacks.handshake_completed){

        rv = conn->tlsref.callbacks.handshake_completed(conn, NULL);
        if (rv != 0) {
            return rv;
        }
    }
    return XQC_OK;
}


xqc_int_t 
xqc_conn_handshake_completed(xqc_connection_t *conn)
{
    conn->tlsref.flags |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX;

    if ((conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED) == 0) {
        conn->handshake_complete_time = xqc_now();
        return xqc_conn_handshake_completed_handled(conn);
    }
    return XQC_OK;
}


xqc_int_t
xqc_conn_early_data_rejected(xqc_connection_t * conn)
{
    conn->tlsref.flags |= XQC_CONN_FLAG_EARLY_DATA_REJECTED;
    if (conn->tlsref.early_data_cb != NULL) {
        return conn->tlsref.early_data_cb(conn, 0);
    }
    return XQC_OK;
}


xqc_int_t
xqc_conn_early_data_accepted(xqc_connection_t * conn)
{
    conn->tlsref.flags &= ~(XQC_CONN_FLAG_EARLY_DATA_REJECTED);
    if(conn->tlsref.early_data_cb != NULL){
        return conn->tlsref.early_data_cb(conn, 1);
    }

    return 0;
}