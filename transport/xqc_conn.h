#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#include "xqc_engine.h"
#include "xqc_transport.h"
#include "xqc_stream.h"

#define XQC_TRANSPORT_VERSION "1.0"

#define XQC_ENCYPT_MAX_LEVEL  4

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

typedef enum {
    XQC_ORININAL_CONNECTION_ID = 0,
    XQC_IDLE_TIMEOUT = 1,
    XQC_STATELESS_RESET_TOKEN = 2,
    XQC_MAX_PACKET_SIZE = 3,
    XQC_MAX_DATA = 4,
    XQC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 5,
    XQC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 6,
    XQC_INITIAL_MAX_STREAM_DATA_UNI = 7,
    XQC_INITIAL_MAX_STREAMS_BIDI = 8,
    XQC_INITIAL_MAX_STREAMS_UNI = 9,
    XQC_ACK_DELAY_EXPONENT = 10,
    XQC_MAX_ACK_DELAY = 11,
    XQC_DISABLE_MIGRATION = 12,
    XQC_PREFERRED_ADDRESS = 13,
    XQC_MAX_TRANS_PARAM_ID
}xqc_trans_param_id_t;

typedef enum {
    XQC_IPV4 = 4,
    XQC_IPV6 = 6,
    XQC_IP_VERSION_MAX = 15
}xqc_ip_version_t;

typedef struct {
    xqc_ip_version_t ip_version;
    unsigned char ip_address[8];
    uint16_t port;
    xqc_cid_t connection_id;
    unsigned char stateless_reset_token[16];
}xqc_preferred_address_t;

typedef struct {
    xqc_cid_t   original_connection_id;
    xqc_msec_t  idle_timeout;
    xqc_buf_t   stateless_reset_token;
    size_t      max_packet_size;
    size_t      initial_max_data;
    uint64_t    initial_max_stream_data_bidi_local;
    uint64_t    initial_max_stream_data_bidi_remote;
    uint64_t    initial_max_stream_data_uni;
    uint64_t    initial_max_streams_bidi;
    uint64_t    initial_max_streams_uni;
    uint64_t    ack_delay_exponent;
    xqc_msec_t  max_ack_delay;
    xqc_flag_t  disable_migration;
    xqc_preferred_address_t preferred_addr;
}xqc_trans_param_t;

struct xqc_connection_s{
    xqc_conn_callbacks_t    conn_callbacks;
    xqc_engine_t            *engine;

    xqc_cid_t               dcid;
    xqc_cid_t               scid;
    xqc_cid_t               ocid; /* original connection id */
    
    xqc_buf_t               token;
   
    xqc_conn_state_t        conn_state;
    xqc_memory_pool_t       *pool;

    xqc_hash_t              *all_streams;
    xqc_stream_t            *crypto_stream[XQC_ENCYPT_MAX_LEVEL];

    xqc_trans_param_t       trans_param;

    void                    *user_data;  /* user_data for application layer */
    
    xqc_log_t               *log;

    /* recovery state ctx */

    /* congestion control ctx */
    /* flag */
};

#endif /* _XQC_CONN_H_INCLUDED_ */
