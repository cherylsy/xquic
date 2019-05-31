
#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * @file
 * Public API for using libxquic
 */

#include <sys/socket.h>
#include <openssl/ssl.h>
#include "xquic_typedef.h"
#define XQC_QUIC_VERSION 1
#define XQC_SUPPORT_VERSION_MAX 64

typedef ssize_t (*xqc_recv_pt)(void *user, unsigned char *buf, size_t size);
typedef ssize_t (*xqc_send_pt)(void *user, unsigned char *buf, size_t size);

typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, void *user_data);

typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *user_data);
typedef int (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *user_data);

struct xqc_conn_callbacks_s {
    xqc_conn_notify_pt          conn_create_notify;
    xqc_conn_notify_pt          conn_close_notify;

    /* for handshake done */
    xqc_handshake_finished_pt   conn_handshake_finished;
};

typedef struct xqc_stream_callbacks_s {
    xqc_stream_notify_pt        stream_read_notify;
    xqc_stream_notify_pt        stream_write_notify;
    xqc_stream_notify_pt        stream_close;
} xqc_stream_callbacks_t;

typedef struct xqc_congestion_control_callback_s {
    size_t (*xqc_cong_ctl_size) ();
    void (*xqc_cong_ctl_init) (void *cong_ctl);
    void (*xqc_cong_ctl_on_lost) (void *cong_ctl, xqc_msec_t lost_sent_time);
    void (*xqc_cong_ctl_on_ack) (void *cong_ctl, xqc_msec_t sent_time, uint32_t n_bytes);
    uint32_t (*xqc_cong_ctl_get_cwnd) (void *cong_ctl);
    void (*xqc_cong_ctl_reset_cwnd) (void *cong_ctl);
} xqc_cong_ctrl_callback_t;


/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {

    size_t  conn_pool_size;
    size_t  streams_hash_bucket_size;
    size_t  conns_hash_bucket_size;
    size_t  conns_pq_capacity;
    uint32_t  support_version_list[XQC_SUPPORT_VERSION_MAX]; /*支持的版本列表*/
    uint32_t  support_version_count; /*版本列表数量*/
}xqc_config_t;


typedef enum {
    XQC_ENGINE_SERVER,
    XQC_ENGINE_CLIENT
}xqc_engine_type_t;


typedef struct xqc_engine_callback_s {
    /* for congestion control */
    xqc_cong_ctrl_callback_t    cong_ctrl_callback;

    /* for socket read & write */
    xqc_recv_pt                 read_socket;
    xqc_send_pt                 write_socket;

    /* for connection notify */
    xqc_conn_callbacks_t        conn_callbacks;

    /* for stream notify */
    xqc_stream_callbacks_t      stream_callbacks;
}xqc_engine_callback_t;

struct xqc_ssl_config {
    char       *private_key_file;
    char       *cert_file;
    char       *session_path;
    char       *tp_path;
    char       *session_ticket_path;
    const char *ciphers;
    const char *groups;
    uint32_t   timeout;
};
typedef struct xqc_ssl_config xqc_ssl_config_t;


typedef struct xqc_engine_s {
    xqc_engine_type_t       eng_type;

    xqc_engine_callback_t   eng_callback;
    xqc_config_t           *config;
    xqc_str_hash_table_t   *conns_hash;
    xqc_pq_t               *conns_pq; /* In process */
    xqc_pq_t               *conns_wakeup_pq; /* Need wakeup after next tick time */

    xqc_conn_settings_t    *settings;

    xqc_log_t              *log;
    xqc_random_generator_t *rand_generator;

    xqc_ssl_config_t       ssl_config; //ssl config, such as cipher suit, cert file path etc.
    SSL_CTX                *ssl_ctx;  //for ssl
}xqc_engine_t;



/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type);

void xqc_engine_destroy(xqc_engine_t *engine);

/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);
void xqc_engine_config_destoy(xqc_config_t *config);


/**
 * Set xquic engine API.
 */
void xqc_engine_set_callback (xqc_engine_t *engine,
                              xqc_engine_callback_t engine_callback);


xqc_connection_t *xqc_engine_connect (xqc_engine_t *engine,
                                      const struct sockaddr *peer_addr,
                                      socklen_t peer_addrlen,
                                      void *user_data);

/**
 * Process all connections
 */
int xqc_engine_main_logic (xqc_engine_t *engine);

/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in millisecond
 */
xqc_int_t xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time);

xqc_connection_t * xqc_client_create_connection(xqc_engine_t *engine,
                                xqc_cid_t dcid, xqc_cid_t scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data);

xqc_connection_t * xqc_connect(xqc_engine_t *engine, void *user_data);

/**
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
xqc_stream_t *xqc_create_stream (xqc_connection_t *c,
                                 void *user_data);

/**
 * Close stream.
 * @retval XQC_OK or XQC_ERROR
 */
int xqc_close_stream (xqc_connection_t *c,
                            uint64_t stream_id);

/**
 * Recv data in stream.
 */
ssize_t xqc_stream_recv (xqc_stream_t *stream,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);

/**
 * Send data in stream.
 * @param fin  0 or 1,  1 - final data block send in this stream.
 */
ssize_t xqc_stream_send (xqc_stream_t *stream,
                         unsigned char *send_data,
                         size_t send_data_size,
                         uint8_t fin);

/**
 * @return >0 : user should call xqc_engine_main_logic after N ms
 */
xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

#endif /* _XQUIC_H_INCLUDED_ */

