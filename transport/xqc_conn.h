#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#include <sys/queue.h>
#include <openssl/ssl.h>
#include "xqc_tls_public.h"
#include "xqc_transport.h"
#include "xqc_stream.h"
#include "xqc_cid.h"
#include "../include/xquic.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_log.h"
#include "xqc_engine.h"
#include "xqc_packet_in.h"
#include "xqc_packet_out.h"
#include "xqc_recv_record.h"

#define XQC_TRANSPORT_VERSION "1.0"

/* 调试时候用，会删掉 */
#ifdef DEBUG_PRINT
#define XQC_DEBUG_PRINT printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);
#else
#define XQC_DEBUG_PRINT
#endif

#define XQC_CONN_ERR(conn, err) do {        \
    conn->conn_err = err;                   \
    conn->conn_flag |= XQC_CONN_FLAG_ERROR; \
} while(0)                                  \

/* 添加state请更新conn_state_2_str */
typedef enum {
    /* server */
    XQC_CONN_STATE_SERVER_INIT = 0,
    XQC_CONN_STATE_SERVER_INITIAL_RECVD,
    XQC_CONN_STATE_SERVER_INITIAL_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD,
    /* client */
    XQC_CONN_STATE_CLIENT_INIT = 5,
    XQC_CONN_STATE_CLIENT_INITIAL_SENT,
    XQC_CONN_STATE_CLIENT_INITIAL_RECVD,
    XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD,
    XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT,
    /* client & server */
    XQC_CONN_STATE_ESTABED = 10,
    XQC_CONN_STATE_CLOSING,
    XQC_CONN_STATE_DRAINING,
    XQC_CONN_STATE_CLOSED,
    XQC_CONN_STATE_N,
}xqc_conn_state_t;

typedef enum {
    XQC_CONN_TYPE_SERVER,
    XQC_CONN_TYPE_CLIENT,
}xqc_conn_type_t;

#define XQC_CONN_FLAG_SHOULD_ACK (XQC_CONN_FLAG_SHOULD_ACK_INIT   \
                                    |XQC_CONN_FLAG_SHOULD_ACK_HSK    \
                                    |XQC_CONN_FLAG_SHOULD_ACK_01RTT) \

#define XQC_CONN_IMMEDIATE_CLOSE_FLAGS (XQC_CONN_FLAG_ERROR)

/* 添加flag请更新conn_flag_2_str */
typedef enum {
    XQC_CONN_FLAG_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT        = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_HSK),
    XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT      = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_01RTT),
    XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_SHIFT_NUM,
}xqc_conn_flag_shift_t;

typedef enum {
    XQC_CONN_FLAG_WAKEUP                = 1 << XQC_CONN_FLAG_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED   = 1 << XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_TICKING               = 1 << XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT       = 1 << XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK        = 1 << XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_01RTT      = 1 << XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT,
    XQC_CONN_FLAG_ACK_HAS_GAP           = 1 << XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT              = 1 << XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR                 = 1 << XQC_CONN_FLAG_ERROR_SHIFT,
}xqc_conn_flag_t;

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
    uint32_t                max_packet_size;
    uint64_t                initial_max_data;
    uint64_t                initial_max_stream_data_bidi_local;
    uint64_t                initial_max_stream_data_bidi_remote;
    uint64_t                initial_max_stream_data_uni;
    uint32_t                initial_max_streams_bidi;
    uint32_t                initial_max_streams_uni;
    uint32_t                ack_delay_exponent;
    xqc_msec_t              max_ack_delay;
    xqc_flag_t              disable_migration;
    xqc_preferred_address_t preferred_addr;
}xqc_trans_param_t;

struct xqc_conn_settings_s {

};

typedef struct {
    /* flow control limit */
    uint64_t                fc_max_data;
    uint64_t                fc_data_sent;
    uint64_t                fc_date_recved;

    uint32_t                fc_max_streams_bidi;
    uint32_t                fc_max_streams_uni;
} xqc_conn_flow_ctl_t;

struct xqc_connection_s{
    xqc_conn_callbacks_t    conn_callbacks;
    xqc_conn_settings_t     conn_settings;
    xqc_engine_t           *engine;

    uint32_t                version;
    uint32_t                discard_vn_flag; /*当客户端收到来自服务器的非VN包或者收到VN包并处理后，设置该标志*/

    xqc_cid_t               dcid;
    xqc_cid_t               scid;
    xqc_cid_t               ocid; /* original connection id */

    xqc_str_t               token;
    xqc_uint_t              zero_rtt_count;

    xqc_conn_state_t        conn_state;
    xqc_memory_pool_t      *conn_pool;

    xqc_id_hash_table_t    *streams_hash;
    xqc_list_head_t         conn_list;
    xqc_list_head_t         conn_write_streams,
                            conn_read_streams, /* xqc_stream_t */
                            conn_all_streams;
    xqc_stream_t           *crypto_stream[XQC_ENC_MAX_LEVEL];
    uint64_t                cur_stream_id_bidi_local;
    uint64_t                cur_stream_id_uni_local;

    xqc_trans_param_t       trans_param;
    xqc_conn_flag_t         conn_flag;
    xqc_conn_type_t         conn_type;

    void                   *user_data;  /* user_data for application layer */

    xqc_list_head_t         packet_in_tailq;  /* xqc_packet_in_t */
    xqc_recv_record_t       recv_record[XQC_PNS_N]; /* record received pkt number range in a list */
    unsigned                ack_eliciting_pkt[XQC_PNS_N]; /* Ack-eliciting Packets received since last ack sent */

    xqc_log_t              *log;

    /* recovery state ctx */

    xqc_send_ctl_t         *conn_send_ctl;

    xqc_msec_t              last_ticked_time;
    xqc_msec_t              next_tick_time;

    SSL                     *xc_ssl;   /*ssl for connection*/
    xqc_tlsref_t            tlsref;   //all tls reference

    xqc_conn_flow_ctl_t     conn_flow_ctl;

    unsigned                wakeup_pq_index;

    xqc_trans_error_code    conn_err;
};

const char* xqc_conn_flag_2_str (xqc_conn_flag_t conn_flag);

const char* xqc_conn_state_2_str(xqc_conn_state_t state);

void xqc_conn_init_trans_param(xqc_connection_t *conn);

void xqc_conn_init_flow_ctl(xqc_connection_t *conn);

int xqc_conns_pq_push (xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_ms);

void xqc_conns_pq_pop (xqc_pq_t *pq);

xqc_conns_pq_elem_t *xqc_conns_pq_top (xqc_pq_t *pq);

int xqc_insert_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid);

int xqc_remove_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid);

xqc_connection_t * xqc_create_connection(xqc_engine_t *engine,
                                xqc_cid_t *dcid, xqc_cid_t *scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data,
                                xqc_conn_type_t type);

void xqc_destroy_connection(xqc_connection_t *xc);

void xqc_conn_send_packets (xqc_connection_t *conn);

ssize_t xqc_conn_send_one_packet (xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_conn_retransmit_lost_packets(xqc_connection_t *conn);

void xqc_conn_retransmit_unacked_crypto(xqc_connection_t *conn);

void xqc_conn_send_probe_packets(xqc_connection_t *conn);

xqc_int_t xqc_conn_check_handshake_completed(xqc_connection_t *conn);

xqc_msec_t xqc_conn_next_wakeup_time(xqc_connection_t *conn);

int xqc_conn_immediate_close(xqc_connection_t *conn);

int xqc_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid, void *user_data);

#endif /* _XQC_CONN_H_INCLUDED_ */
