#ifndef XQC_TLS_STACK_CB_H_
#define XQC_TLS_STACK_CB_H_

#include <xquic/xquic.h>


// check if handshake has completed 
xqc_bool_t xqc_conn_get_handshake_completed(xqc_connection_t *conn);

/**
 *  call when tls stack completed the handshake 
 * */
xqc_int_t xqc_conn_handshake_completed(xqc_connection_t *conn) ;

/**
 * call when tls stack rejected the 0-RTT data 
 * */
xqc_int_t xqc_conn_early_data_rejected(xqc_connection_t * conn);

/**
 * call when tls stack accepted the 0-RTT data
 * bu we nerver call 
 * */
xqc_int_t xqc_conn_early_data_accepted(xqc_connection_t * conn);


#endif //XQC_TLS_STACK_CB_H_