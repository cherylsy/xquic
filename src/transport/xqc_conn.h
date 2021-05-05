#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_recv_record.h"

#define XQC_TRANSPORT_VERSION "1.0"

/*
 * XQC_DEFAULT_MAX_ACK_DELAY is a default value of the maximum
 * amount of time in milliseconds by which endpoint delays sending
 * acknowledgement.
 */
#define XQC_DEFAULT_MAX_ACK_DELAY 25

/*
 * XQC_DEFAULT_ACK_DELAY_EXPONENT is a default value of scaling
 * factor of ACK Delay field in ACK frame.
 */
#define XQC_DEFAULT_ACK_DELAY_EXPONENT 3

#define XQC_MAX_UDP_PAYLOAD_SIZE 65527 /* quic protocol define */

#define XQC_STATELESS_RESET_TOKENLEN 16
#define XQC_MAX_TOKEN_LEN 32

#define XQC_TOKEN_EXPIRE_DELTA (7*24*60*60) /* expire in N seconds */
#define XQC_TOKEN_UPDATE_DELTA (XQC_TOKEN_EXPIRE_DELTA / 2) /* early update */

#define XQC_MAX_AVAILABLE_CID_COUNT  16

#define XQC_MAX_PACKET_PROCESS_BATCH 100 /* maximum accumulated number of xqc_engine_packet_process */

#define XQC_MAX_RECV_WINDOW (16*1024*1024)

/* the max_streams transmission parameter or the value received in the MAX_STREAMS frame must <= 2^60 */
#define XQC_MAX_STREAMS ((uint64_t)1 << 60)

static const uint32_t MAX_RSP_CONN_CLOSE_CNT = 3;

/* for debugging, will be deleted later */
#ifdef DEBUG_PRINT
#define XQC_DEBUG_PRINT printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);
#else
#define XQC_DEBUG_PRINT
#endif

/* send CONNECTION_CLOSE with err */
#define XQC_CONN_ERR(conn, err) do {            \
    if ((conn)->conn_err == 0) {                \
        (conn)->conn_err = (err);               \
        (conn)->conn_flag |= XQC_CONN_FLAG_ERROR; \
        xqc_log((conn)->log, XQC_LOG_ERROR, "|conn:%p|err:0x%xi|%s|", (conn), (uint64_t)(err), xqc_conn_addr_str(conn)); \
    }                                       \
} while(0)                                  \

extern xqc_conn_settings_t default_conn_settings;

/* !!WARNING: to add state, please update conn_state_2_str */
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

/* !!WARNING: to add flag, please update conn_flag_2_str */
typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT        = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_HSK),
    XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT      = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_APP_DATA),
    XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_DATA_BLOCKED_SHIFT,
    XQC_CONN_FLAG_DCID_OK_SHIFT,
    XQC_CONN_FLAG_TOKEN_OK_SHIFT,
    XQC_CONN_FLAG_HAS_0RTT_SHIFT,
    XQC_CONN_FLAG_0RTT_OK_SHIFT,
    XQC_CONN_FLAG_0RTT_REJ_SHIFT,
    XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT,
    XQC_CONN_FLAG_SVR_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_CANNOT_DESTROY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_RECEIVED_SHIFT,
    XQC_CONN_FLAG_SHIFT_NUM,
}xqc_conn_flag_shift_t;

typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP           = 1 << XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED   = 1 << XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT         = 1 << XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING               = 1 << XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT       = 1 << XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK        = 1 << XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_01RTT      = 1 << XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT,
    XQC_CONN_FLAG_ACK_HAS_GAP           = 1 << XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT              = 1 << XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR                 = 1 << XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_DATA_BLOCKED          = 1 << XQC_CONN_FLAG_DATA_BLOCKED_SHIFT,
    XQC_CONN_FLAG_DCID_OK               = 1 << XQC_CONN_FLAG_DCID_OK_SHIFT,
    XQC_CONN_FLAG_TOKEN_OK              = 1 << XQC_CONN_FLAG_TOKEN_OK_SHIFT,
    XQC_CONN_FLAG_HAS_0RTT              = 1 << XQC_CONN_FLAG_HAS_0RTT_SHIFT,
    XQC_CONN_FLAG_0RTT_OK               = 1 << XQC_CONN_FLAG_0RTT_OK_SHIFT,
    XQC_CONN_FLAG_0RTT_REJ              = 1 << XQC_CONN_FLAG_0RTT_REJ_SHIFT,
    XQC_CONN_FLAG_UPPER_CONN_EXIST      = 1 << XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT,
    XQC_CONN_FLAG_SVR_INIT_RECVD        = 1 << XQC_CONN_FLAG_SVR_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN              = 1 << XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING                  = 1 << XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED             = 1 << XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_CANNOT_DESTROY        = 1 << XQC_CONN_FLAG_CANNOT_DESTROY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD  = 1 << XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN      = 1 << XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION   = 1 << XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED   = 1 << XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED        = 1 << XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_RECEIVED      = 1 << XQC_CONN_FLAG_NEW_CID_RECEIVED_SHIFT,
}xqc_conn_flag_t;


typedef struct {
    uint8_t     ipv4[4];    
    uint16_t    ipv4_port;
    uint8_t     ipv6[16];
    uint16_t    ipv6_port;
    xqc_cid_t   cid;
    uint8_t     stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_preferred_addr_t;

#define XQC_PREFERRED_ADDR_IPV4_LEN         4
#define XQC_PREFERRED_ADDR_IPV4_PORT_LEN    2
#define XQC_PREFERRED_ADDR_IPV6_LEN         16
#define XQC_PREFERRED_ADDR_IPV6_PORT_LEN    2


/* For Handshake */
typedef struct {
    xqc_preferred_addr_t    preferred_address;
    uint8_t                 preferred_address_present;

    xqc_cid_t               original_dest_connection_id;
    uint8_t                 original_dest_connection_id_present;

    xqc_msec_t              max_idle_timeout;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 stateless_reset_token_present;
    uint64_t                max_udp_payload_size;
    uint64_t                initial_max_data;
    uint64_t                initial_max_stream_data_bidi_local;
    uint64_t                initial_max_stream_data_bidi_remote;
    uint64_t                initial_max_stream_data_uni;
    uint64_t                initial_max_streams_bidi;
    uint64_t                initial_max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_msec_t              max_ack_delay;
    xqc_flag_t              disable_active_migration;
    uint64_t                active_connection_id_limit;
    xqc_cid_t               initial_source_connection_id;
    uint8_t                 initial_source_connection_id_present;
    xqc_cid_t               retry_source_connection_id;
    uint8_t                 retry_source_connection_id_present;

    uint64_t                no_crypto;

    uint64_t                enable_multipath;
} xqc_transport_params_t;

#define XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT 8


typedef struct {
    xqc_preferred_addr_t    preferred_address;
    xqc_msec_t              max_idle_timeout;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 stateless_reset_token_present;
    uint64_t                max_udp_payload_size;
    uint64_t                max_data;
    uint64_t                max_stream_data_bidi_local;
    uint64_t                max_stream_data_bidi_remote;
    uint64_t                max_stream_data_uni;
    uint64_t                max_streams_bidi;
    uint64_t                max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_msec_t              max_ack_delay;
    xqc_flag_t              disable_active_migration;
    uint64_t                active_connection_id_limit;
    uint64_t                no_crypto;
    uint64_t                enable_multipath;
} xqc_trans_settings_t;


typedef struct {
    /* flow control limit */
    uint64_t                fc_max_data_can_send;
    uint64_t                fc_data_sent;
    uint64_t                fc_max_data_can_recv;
    uint64_t                fc_data_recved;
    uint64_t                fc_data_read;

    uint64_t                fc_max_streams_bidi_can_send;
    uint64_t                fc_max_streams_bidi_can_recv;
    uint64_t                fc_max_streams_uni_can_send;
    uint64_t                fc_max_streams_uni_can_recv;

    uint64_t                fc_recv_windows_size;
    xqc_msec_t              fc_last_window_update_time;
} xqc_conn_flow_ctl_t;

#ifdef XQC_PRINT_SECRET
#define XQC_SECRET_HEX_MAX 129
typedef enum xqc_secret_type_s {
    CLIENT_EARLY_TRAFFIC_SECRET,
    CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    SERVER_HANDSHAKE_TRAFFIC_SECRET,
    CLIENT_TRAFFIC_SECRET_0,
    SERVER_TRAFFIC_SECRET_0,
    SECRET_TYPE_NUM,
} xqc_secret_type_t;
#endif

struct xqc_connection_s{
    xqc_conn_callbacks_t    conn_callbacks;
    xqc_stream_callbacks_t  stream_callbacks;
    xqc_conn_settings_t     conn_settings;
    xqc_engine_t           *engine;

    xqc_proto_version_t     version;
    /* set when client receives a non-VN package from server or receives a VN package and processes it */
    uint32_t                discard_vn_flag;

    xqc_cid_t               dcid; /* peer connection id */
    xqc_cid_t               scid; /* local connection id */
    xqc_cid_t               ocid; /* original connection id */
    unsigned char           dcid_str[XQC_MAX_CID_LEN * 2 + 1];
    unsigned char           scid_str[XQC_MAX_CID_LEN * 2 + 1];
    uint64_t                largest_scid_seq_num;

    xqc_cid_t               avail_dcid[XQC_MAX_AVAILABLE_CID_COUNT];
    uint32_t                avail_dcid_count;
    xqc_cid_t               avail_scid[XQC_MAX_AVAILABLE_CID_COUNT];
    uint32_t                avail_scid_count;

    unsigned char           peer_addr[sizeof(struct sockaddr_in6)],
                            local_addr[sizeof(struct sockaddr_in6)];
    socklen_t               peer_addrlen,
                            local_addrlen;

    char                    addr_str[2*(XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];
    size_t                  addr_str_len;

    unsigned char           conn_token[XQC_MAX_TOKEN_LEN];
    unsigned char           enc_pkt[XQC_PACKET_OUT_SIZE_EXT];
    size_t                  enc_pkt_len;
    uint32_t                conn_token_len;
    uint32_t                zero_rtt_count;
    uint32_t                retry_count;
    uint32_t                conn_close_count;
    uint32_t                packet_need_process_count; /* xqc_engine_packet_process积累个数 */

    xqc_conn_state_t        conn_state;
    xqc_memory_pool_t      *conn_pool;

    xqc_id_hash_table_t    *streams_hash;
    xqc_id_hash_table_t    *passive_streams_hash;
    xqc_list_head_t         conn_write_streams,
                            conn_read_streams, /* xqc_stream_t */
                            conn_closing_streams,
                            conn_all_streams;
    xqc_stream_t           *crypto_stream[XQC_ENC_MAX_LEVEL];
    uint64_t                cur_stream_id_bidi_local;
    uint64_t                cur_stream_id_uni_local;
    int64_t                 max_stream_id_bidi_remote;
    int64_t                 max_stream_id_uni_remote;

    xqc_trans_settings_t    local_settings;
    xqc_trans_settings_t    remote_settings;
    xqc_conn_flag_t         conn_flag;
    xqc_conn_type_t         conn_type;

    void                   *user_data;  /* user_data for application layer */

    xqc_list_head_t         undecrypt_packet_in[XQC_ENC_MAX_LEVEL];  /* xqc_packet_in_t */
    uint32_t                undecrypt_count[XQC_ENC_MAX_LEVEL];

    xqc_recv_record_t       recv_record[XQC_PNS_N]; /* record received pkt number range in a list */
    uint32_t                ack_eliciting_pkt[XQC_PNS_N]; /* Ack-eliciting Packets received since last ack sent */

    xqc_log_t              *log;

    xqc_send_ctl_t         *conn_send_ctl;
    //xqc_send_ctl_info_t     ctl_info;

    xqc_msec_t              last_ticked_time;
    xqc_msec_t              next_tick_time;
    xqc_msec_t              conn_create_time;
    xqc_msec_t              handshake_complete_time; /* record the time when the handshake ends */
    xqc_msec_t              first_data_send_time;    /* record the time when the bidirectional stream first sent data */

    SSL                     *xc_ssl; /* ssl for connection */
    xqc_tlsref_t            tlsref;  /* all tls reference */

    xqc_conn_flow_ctl_t     conn_flow_ctl;

    uint32_t                wakeup_pq_index;

    uint64_t                conn_err;

    /* for multi-path */
    xqc_path_ctx_t         *conn_initial_path;
    xqc_list_head_t         conn_paths_list;


#ifdef XQC_PRINT_SECRET
    unsigned char           client_random_hex[XQC_SECRET_HEX_MAX];
    unsigned char           secret_hex[SECRET_TYPE_NUM][XQC_SECRET_HEX_MAX];
#endif
};

const char*
xqc_conn_flag_2_str(xqc_conn_flag_t conn_flag);

const char*
xqc_conn_state_2_str(xqc_conn_state_t state);

void
xqc_conn_init_trans_param(xqc_connection_t *conn);

void
xqc_conn_init_flow_ctl(xqc_connection_t *conn);

xqc_connection_t *
xqc_conn_create(xqc_engine_t *engine, xqc_cid_t *dcid, xqc_cid_t *scid, xqc_conn_callbacks_t *callbacks,
    xqc_conn_settings_t *settings, void *user_data, xqc_conn_type_t type);

xqc_connection_t *
xqc_conn_server_create(xqc_engine_t *engine, const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, xqc_cid_t *dcid, xqc_cid_t *scid,
    xqc_conn_callbacks_t *callbacks, xqc_conn_settings_t *settings, void *user_data);

void
xqc_conn_destroy(xqc_connection_t *xc);

void
xqc_conn_server_on_alpn(xqc_connection_t *conn);

ssize_t
xqc_conn_send_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void
xqc_conn_send_packets(xqc_connection_t *conn);

void
xqc_conn_send_packets_batch(xqc_connection_t *conn);

xqc_int_t
xqc_conn_enc_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, 
                    char *enc_pkt, size_t * enc_pkt_len, xqc_msec_t current_time);

void
xqc_conn_transmit_pto_probe_packets(xqc_connection_t *conn);

void
xqc_conn_transmit_pto_probe_packets_batch(xqc_connection_t *conn);

void
xqc_conn_retransmit_lost_packets(xqc_connection_t *conn);

void
xqc_conn_retransmit_lost_packets_batch(xqc_connection_t *conn);

void
xqc_conn_send_one_or_two_ack_elicit_pkts(xqc_connection_t *c, xqc_pkt_num_space_t pns);

void
xqc_conn_send_one_ack_eliciting_pkt(xqc_connection_t *conn, xqc_pkt_num_space_t pns);

xqc_int_t
xqc_conn_check_handshake_completed(xqc_connection_t *conn);

xqc_int_t
xqc_conn_is_handshake_confirmed(xqc_connection_t *conn);

xqc_int_t
xqc_conn_immediate_close(xqc_connection_t *conn);

xqc_int_t
xqc_conn_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid, void *user_data,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen);

xqc_int_t
xqc_conn_send_retry(xqc_connection_t *conn, unsigned char *token, unsigned token_len);

xqc_int_t
xqc_conn_version_check(xqc_connection_t *c, uint32_t version);

xqc_int_t
xqc_conn_send_version_negotiation(xqc_connection_t *c);

xqc_int_t
xqc_conn_check_token(xqc_connection_t *conn, const unsigned char *token, unsigned token_len);

void
xqc_conn_gen_token(xqc_connection_t *conn, unsigned char *token, unsigned *token_len);

xqc_int_t
xqc_conn_early_data_reject(xqc_connection_t *conn);

xqc_int_t
xqc_conn_early_data_accept(xqc_connection_t *conn);

xqc_int_t
xqc_conn_handshake_complete(xqc_connection_t *conn);

xqc_int_t
xqc_conn_buff_undecrypt_packet_in(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level);

xqc_int_t
xqc_conn_process_undecrypt_packet_in(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level);

void
xqc_conn_buff_1rtt_packets(xqc_connection_t *conn);

void
xqc_conn_write_buffed_1rtt_packets(xqc_connection_t *conn);

xqc_msec_t
xqc_conn_next_wakeup_time(xqc_connection_t *conn);

char *
xqc_conn_local_addr_str(const struct sockaddr *local_addr,
                        socklen_t local_addrlen);

char *
xqc_conn_peer_addr_str(const struct sockaddr *peer_addr,
                       socklen_t peer_addrlen);

char *
xqc_conn_addr_str(xqc_connection_t *conn);

static inline void
xqc_conn_process_undecrypt_packets(xqc_connection_t *conn)
{
    if (conn->undecrypt_count[XQC_ENC_LEV_1RTT] > 0 && conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_1RTT);
    }
    if (conn->undecrypt_count[XQC_ENC_LEV_0RTT] > 0 && xqc_tls_check_0rtt_key_ready(conn)) {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_0RTT);
    }
    if (conn->undecrypt_count[XQC_ENC_LEV_HSK] > 0 && xqc_tls_check_hs_rx_key_ready(conn)) {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_HSK);
    }
}

static inline xqc_int_t
xqc_conn_has_undecrypt_packets(xqc_connection_t *conn)
{
    return conn->undecrypt_count[XQC_ENC_LEV_1RTT]
           || conn->undecrypt_count[XQC_ENC_LEV_0RTT]
           || conn->undecrypt_count[XQC_ENC_LEV_HSK];
}

static inline xqc_int_t
xqc_conn_should_ack(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|should_generate_ack yes|flag:%s|",
                xqc_conn_flag_2_str(conn->conn_flag));
        return 1;
    }
    return 0;
}

/* process an UDP datagram */
xqc_int_t xqc_conn_process_packet(xqc_connection_t *c, const unsigned char *packet_in_buf,
                        size_t packet_in_size, xqc_msec_t recv_time);

xqc_int_t xqc_conn_check_handshake_complete(xqc_connection_t *conn);


xqc_int_t xqc_conn_get_new_dcid(xqc_connection_t *conn,
    xqc_cid_t *dcid);
xqc_int_t xqc_conn_get_new_scid(xqc_connection_t *conn,
    xqc_cid_t *scid);
xqc_int_t xqc_conn_check_available_cids(xqc_connection_t *conn);
void xqc_conn_try_add_new_conn_id(xqc_connection_t *conn);
xqc_cid_t *xqc_conn_get_scid_by_seq(xqc_connection_t *conn, uint64_t seq_num);
xqc_cid_t *xqc_conn_get_dcid_by_seq(xqc_connection_t *conn, uint64_t seq_num);
xqc_int_t xqc_conn_check_dcid(xqc_connection_t *conn, xqc_cid_t *dcid);
void xqc_conn_destroy_cids(xqc_connection_t *conn);

xqc_bool_t
xqc_conn_peer_complete_address_validation(xqc_connection_t *c);

xqc_bool_t
xqc_conn_has_hsk_keys(xqc_connection_t *c);


#endif /* _XQC_CONN_H_INCLUDED_ */
