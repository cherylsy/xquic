#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#include <sys/queue.h>
#include "xqc_transport.h"
#include "xqc_stream.h"
#include "xqc_cid.h"
#include "../include/xquic.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_log.h"

#define XQC_TRANSPORT_VERSION "1.0"

#define XQC_ENCYPT_MAX_LEVEL  4

typedef struct xqc_conn_callbacks_s{

}xqc_conn_callbacks_t;

typedef enum {
    /* server */
    XQC_CONN_STATE_SERVER_INIT,
    XQC_CONN_STATE_SERVER_INITIAL_RECVD,
    XQC_CONN_STATE_SERVER_INITIAL_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD,
    /* client */
    XQC_CONN_STATE_CLIENT_INIT,
    /* client & server */
    XQC_CONN_STATE_ESTABED,
    XQC_CONN_STATE_CLOSING,
    XQC_CONN_STATE_DRAINING,
    XQC_CONN_STATE_CLOSED
}xqc_conn_state_t;

typedef enum {
    XQC_CONN_TYPE_SERVER,
    XQC_CONN_TYPE_CLIENT,
}xqc_conn_type_t;

typedef enum {
    XQC_TRANS_PARAM_ORININAL_CONNECTION_ID = 0,
    XQC_TRANS_PARAM_IDLE_TIMEOUT = 1,
    XQC_TRANS_PARAM_STATELESS_RESET_TOKEN = 2,
    XQC_TRANS_PARAM_MAX_PACKET_SIZE = 3,
    XQC_TRANS_PARAM_MAX_DATA = 4,
    XQC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 5,
    XQC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 6,
    XQC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 7,
    XQC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI = 8,
    XQC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI = 9,
    XQC_TRANS_PARAM_ACK_DELAY_EXPONENT = 10,
    XQC_TRANS_PARAM_MAX_ACK_DELAY = 11,
    XQC_TRANS_PARAM_DISABLE_MIGRATION = 12,
    XQC_TRANS_PARAM_PREFERRED_ADDRESS = 13,
    XQC_TRANS_PARAM_MAX_TRANS_PARAM_ID
}xqc_trans_param_id_t;

typedef enum {
    XQC_IPV4 = 4,
    XQC_IPV6 = 6,
    XQC_IP_VERSION_MAX = 15
}xqc_ip_version_t;

typedef struct {
    xqc_ip_version_t    ip_version;
    unsigned char       ip_address[8];
    uint16_t            port;
    xqc_cid_t           connection_id;
    unsigned char       stateless_reset_token[16];
}xqc_preferred_address_t;

typedef struct {
    xqc_cid_t               original_connection_id;
    xqc_msec_t              idle_timeout;
    xqc_buf_t               stateless_reset_token;
    size_t                  max_packet_size;
    size_t                  initial_max_data;
    uint64_t                initial_max_stream_data_bidi_local;
    uint64_t                initial_max_stream_data_bidi_remote;
    uint64_t                initial_max_stream_data_uni;
    uint64_t                initial_max_streams_bidi;
    uint64_t                initial_max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_msec_t              max_ack_delay;
    xqc_flag_t              disable_migration;
    xqc_preferred_address_t preferred_addr;
}xqc_trans_param_t;

struct xqc_conn_settings_s {

};

TAILQ_HEAD(xqc_stream_tailq, xqc_stream_t);
typedef struct xqc_stream_tailq xqc_stream_tailq_t;

struct xqc_connection_s{
    xqc_conn_callbacks_t    conn_callbacks;
    xqc_conn_settings_t     conn_settings;
    xqc_engine_t           *engine;

    uint32_t                version;

    xqc_cid_t               dcid;
    xqc_cid_t               scid;
    xqc_cid_t               ocid; /* original connection id */
    
    xqc_buf_t               token;
   
    xqc_conn_state_t        conn_state;
    xqc_memory_pool_t      *conn_pool;

    xqc_id_hash_table_t    *streams_hash;
    xqc_stream_tailq_t      conn_write_streams,
                            conn_read_streams;
    xqc_stream_t           *crypto_stream[XQC_ENCYPT_MAX_LEVEL];
    uint64_t                cur_stream_id_bidi_local;
    uint64_t                cur_stream_id_uni_local;

    xqc_trans_param_t       trans_param;

    void                   *user_data;  /* user_data for application layer */
    
    xqc_log_t              *log;

    /* recovery state ctx */

    /* congestion control ctx */
    xqc_send_ctl_t         *conn_send_ctl;
    /* flag */
};

xqc_connection_t * xqc_create_connection(xqc_engine_t *engine, 
                                xqc_cid_t dcid, xqc_cid_t scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data, 
                                xqc_conn_type_t type);

void xqc_destroy_connection(xqc_connection_t *xc);

void xqc_conn_send_packets (xqc_connection_t *conn);

#endif /* _XQC_CONN_H_INCLUDED_ */
