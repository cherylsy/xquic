
#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * @file
 * Public API for using libxquic
 */
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include "xquic_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_QUIC_VERSION 1
#define XQC_SUPPORT_VERSION_MAX 64

#define XQC_TLS_CIPHERS "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
#define XQC_TLS_GROUPS "P-256:X25519:P-384:P-521"

#define XQC_TLS_AEAD_OVERHEAD_MAX_LEN 16

typedef void (*xqc_set_event_timer_pt)(void *engine_user_data, xqc_msec_t wake_after);

typedef void (*xqc_save_token_pt)(void *conn_user_data, const unsigned char *token, uint32_t token_len);

/*
 * warning: server's user_data is NULL when send a reset packet
 * return bytes sent, <0 for error
 */
typedef ssize_t (*xqc_socket_write_pt)(void *conn_user_data, unsigned char *buf, size_t size,
                                       const struct sockaddr *peer_addr,
                                       socklen_t peer_addrlen);

typedef enum {
    XQC_REQ_NOTIFY_READ_HEADER  = 1 << 0,
    XQC_REQ_NOTIFY_READ_BODY    = 1 << 1,
} xqc_request_notify_flag_t;

/*
 * return 0 for success, <0 for error
 */
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data);
typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *h3_conn, xqc_cid_t *cid, void *user_data);
typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *user_data);
typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *user_data);
typedef int (*xqc_h3_request_read_notify_pt)(xqc_h3_request_t *h3_request, void *user_data, xqc_request_notify_flag_t flag);

typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *user_data);
typedef void (*xqc_h3_handshake_finished_pt)(xqc_h3_conn_t *h3_conn, void *user_data);

/* user_data is a parameter of xqc_engine_packet_process */
typedef int (*xqc_server_accept_pt)(xqc_engine_t *engine, xqc_connection_t *conn, xqc_cid_t *cid, void *user_data);

//session save callback
typedef int  (*xqc_save_session_cb_t)(char *data, size_t data_len, void *conn_user_data);
//transport parameters save callback
typedef int  (*xqc_save_tp_cb_t)(char *data, size_t data_len, void *conn_user_data);

/* log interface */
typedef struct xqc_log_callbacks_s {
    /* return 0 for success, <0 for error */
    int (*xqc_open_log_file)(void *engine_user_data);
    int (*xqc_close_log_file)(void *engine_user_data);
    /* return bytes write, <0 for error*/
    ssize_t (*xqc_write_log_file)(void *engine_user_data, const void *buf, size_t size);
    xqc_log_level_t log_level;
} xqc_log_callbacks_t;

/* transport layer */
typedef struct xqc_conn_callbacks_s {
    /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_conn_notify_pt          conn_create_notify; /* required for server, optional for client */
    /* 连接关闭时回调,用户可以回收资源 */
    xqc_conn_notify_pt          conn_close_notify;
    /* for handshake done */
    xqc_handshake_finished_pt   conn_handshake_finished;  /* optional */
} xqc_conn_callbacks_t;

/* application layer */
typedef struct xqc_h3_conn_callbacks_s {
    /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_h3_conn_notify_pt          h3_conn_create_notify; /* required for server, optional for client */
    /* 连接关闭时回调,用户可以回收资源 */
    xqc_h3_conn_notify_pt          h3_conn_close_notify;
    /* for handshake done */
    xqc_h3_handshake_finished_pt   h3_conn_handshake_finished;  /* optional */
} xqc_h3_conn_callbacks_t;

/* transport layer */
typedef struct xqc_stream_callbacks_s {
    xqc_stream_notify_pt        stream_read_notify; /* 可读时回调，用户可以继续调用读接口 */
    xqc_stream_notify_pt        stream_write_notify; /* 可写时回调，用户可以继续调用写接口 */
    xqc_stream_notify_pt        stream_create_notify;  /* required for server, optional for client，
                                                         * 请求创建完成后回调，用户可以创建自己的请求上下文 */
    xqc_stream_notify_pt        stream_close_notify;   /* 关闭时回调，用户可以回收资源 */
} xqc_stream_callbacks_t;

/* application layer */
typedef struct xqc_h3_request_callbacks_s {
    xqc_h3_request_read_notify_pt   h3_request_read_notify; /* 可读时回调，用户可以继续调用读接口，读headers或body */
    xqc_h3_request_notify_pt        h3_request_write_notify; /* 可写时回调，用户可以继续调用写接口,写headers或body */
    xqc_h3_request_notify_pt        h3_request_create_notify; /* required for server, optional for client，
                                                            * 请求创建完成后回调，用户可以创建自己的请求上下文 */
    xqc_h3_request_notify_pt        h3_request_close_notify; /* 关闭时回调，用户可以回收资源 */
} xqc_h3_request_callbacks_t;

typedef struct xqc_congestion_control_callback_s {
    size_t (*xqc_cong_ctl_size) ();
    void (*xqc_cong_ctl_init) (void *cong_ctl);
    void (*xqc_cong_ctl_on_lost) (void *cong_ctl, xqc_msec_t lost_sent_time);
    void (*xqc_cong_ctl_on_ack) (void *cong_ctl, xqc_msec_t sent_time, uint32_t n_bytes);
    uint32_t (*xqc_cong_ctl_get_cwnd) (void *cong_ctl);
    void (*xqc_cong_ctl_reset_cwnd) (void *cong_ctl);
    int (*xqc_cong_ctl_in_slow_start) (void *cong_ctl);

    //For BBR
    void (*xqc_cong_ctl_bbr) (void *cong_ctl, xqc_sample_t *sampler);
    void (*xqc_cong_ctl_init_bbr) (void *cong_ctl, xqc_sample_t *sampler);
    uint32_t (*xqc_cong_ctl_get_pacing_rate) (void *cong_ctl);
    uint32_t (*xqc_cong_ctl_get_bandwidth_estimate) (void *cong_ctl);
} xqc_cong_ctrl_callback_t;

extern const xqc_cong_ctrl_callback_t xqc_bbr_cb;
extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;
extern const xqc_cong_ctrl_callback_t xqc_reno_cb;

/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {
    size_t  conn_pool_size;
    size_t  streams_hash_bucket_size;
    size_t  conns_hash_bucket_size;
    size_t  conns_active_pq_capacity;
    size_t  conns_wakeup_pq_capacity;
    uint32_t  support_version_list[XQC_SUPPORT_VERSION_MAX]; /*支持的版本列表*/
    uint32_t  support_version_count; /*版本列表数量*/
    uint8_t   cid_len;
} xqc_config_t;


typedef enum {
    XQC_ENGINE_SERVER,
    XQC_ENGINE_CLIENT
} xqc_engine_type_t;

/**
 * User should implement following callbacks.
 */
typedef struct xqc_engine_callback_s {
    /* for event loop */
    xqc_set_event_timer_pt      set_event_timer; /* 设置定时器回调，定时器到期时用户需要调用xqc_engine_main_logic */

    /* for socket write */
    xqc_socket_write_pt         write_socket; /* 用户实现socket写接口 */

    /* for server, callback when server accept a new connection */
    xqc_server_accept_pt        server_accept;

    /* for connection notify */
    xqc_conn_callbacks_t        conn_callbacks;

    /* for h3 connection notify */
    xqc_h3_conn_callbacks_t     h3_conn_callbacks;

    /* for stream notify */
    xqc_stream_callbacks_t      stream_callbacks;

    /* for request notify */
    xqc_h3_request_callbacks_t  h3_request_callbacks;

    /* for write log file */
    xqc_log_callbacks_t         log_callbacks;

    /* for client, 保存token到本地，connect时带上token, token包含客户端ip信息，用于验证客户端ip是否真实 */
    xqc_save_token_pt           save_token;

    /* for client, save session data, Use the domain as the key to save */
    xqc_save_session_cb_t       save_session_cb;

    /* for client, save transport parameter data, Use the domain as the key to save */
    xqc_save_tp_cb_t            save_tp_cb;
} xqc_engine_callback_t;

#define XQC_ALPN_HTTP3 "http3-1"
#define XQC_ALPN_TRANSPORT "transport"

typedef struct xqc_engine_ssl_config_s {
    char       *private_key_file; /* For server */
    char       *cert_file; /* For server */
    char       *ciphers;
    char       *groups;
    //uint32_t   timeout;
    char       *session_ticket_key_data; /* For server */
    size_t     session_ticket_key_len; /* For server */

    char       *alpn_list; /* For server */
    int        alpn_list_len; /* For server */
} xqc_engine_ssl_config_t;

typedef struct xqc_conn_ssl_config_s {
    char       *session_ticket_data; /* For client, client should Use the domain as the key to save */
    size_t     session_ticket_len;  /* For client */
    char       *transport_parameter_data; /* For client, client should Use the domain as the key to save */
    size_t     transport_parameter_data_len; /* For client */

    char       *alpn; /* User does't care */
} xqc_conn_ssl_config_t;


typedef struct xqc_http_header_s {
    struct iovec        name;
    struct iovec        value;
    uint8_t             flags; /* 1:do not compress this header */
} xqc_http_header_t;

typedef struct xqc_http_headers_s {
    xqc_http_header_t       *headers;
    size_t                  count;
    size_t                  capacity; /* User does't care */
} xqc_http_headers_t;

/* For client */
typedef struct xqc_conn_settings_s {
    int     pacing_on; /* default: 0 */
    xqc_cong_ctrl_callback_t    cong_ctrl_callback; /* default: xqc_cubic_cb */
    int     ping_on;    /* client sends PING to keepalive, default:0 */
} xqc_conn_settings_t;

typedef enum {
    XQC_0RTT_NONE, /* without 0RTT */
    XQC_0RTT_ACCEPT,
    XQC_0RTT_REJECT,
} xqc_0rtt_flag_t;

typedef struct xqc_conn_stats_s {
    uint32_t    send_count;
    uint32_t    lost_count;
    uint32_t    tlp_count;
    xqc_msec_t  srtt;
    xqc_0rtt_flag_t    early_data_flag;
} xqc_conn_stats_t;

typedef struct xqc_request_stats_s {
    size_t      send_body_size;
    size_t      recv_body_size;
} xqc_request_stats_t;

/**
 * Modify engine config before engine created. Default config will be used otherwise.
 * Item value 0 means use default value.
 * @return 0 for success, <0 for error. default value is used if config item is illegal
 */
int xqc_set_engine_config(xqc_config_t *config, xqc_engine_type_t engine_type);

/**
 * For server, it can be called anytime. settings will take effect on new connections
 */
void xqc_server_set_conn_settings(xqc_conn_settings_t settings);

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
                                xqc_engine_ssl_config_t * ssl_config,
                                xqc_engine_callback_t engine_callback,
                                void *user_data);

void xqc_engine_destroy(xqc_engine_t *engine);


/**
 * Client connect with http3
 * @param engine return from xqc_engine_create
 * @param user_data For connection
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len
 * @param server_host server domain
 * @param no_crypto_flag 1:without crypto
 * @param conn_ssl_config For handshake
 * @return scid of the connection; user should copy cid to your own memory, in case of cid destroyed in xquic library
 */
xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, void *user_data,
                          xqc_conn_settings_t conn_settings,
                          unsigned char *token, unsigned token_len,
                          char *server_host, int no_crypto_flag,
                          xqc_conn_ssl_config_t *conn_ssl_config,
                          const struct sockaddr *peer_addr,
                          socklen_t peer_addrlen);

int xqc_h3_conn_close(xqc_engine_t *engine, xqc_cid_t *cid);

/**
 * Get cid in hex, end with '\0'
 * @param cid means scid
 */
unsigned char* xqc_scid_str(const xqc_cid_t *cid);

/**
 * Get errno when h3_conn_close_notify, 0 For no-error
 */
int xqc_h3_conn_get_errno(xqc_h3_conn_t *h3_conn);

/**
 * Server should set user_data when h3_conn_create_notify callbacks
 */
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3_conn,
                               void *user_data);

/**
 * Server should get peer addr when h3_conn_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return peer addr
 */
struct sockaddr* xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3_conn,
                                           socklen_t *peer_addr_len);

/**
 * Server should get local addr when h3_conn_create_notify callbacks
 * @param local_addr_len is a return value
 * @return local addr
 */
struct sockaddr* xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3_conn,
                                           socklen_t *local_addr_len);

/**
 * @param user_data For request
 */
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine,
                                        xqc_cid_t *cid,
                                        void *user_data);

/**
 * User can get xqc_request_stats_t before request destroyed
 */
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);

/**
 * Server should set user_data when h3_request_create_notify callbacks
 */
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request,
                                  void *user_data);

/**
 * Get connection's user_data by request
 */
void* xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);

/**
 * Get stream ID by request
 */
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);

/**
 * Send RESET_STREAM to peer, h3_request_close_notify will callback when request destroyed
 * @retval 0 for success, <0 for error
 */
int xqc_h3_request_close (xqc_h3_request_t *h3_request);

/**
 * @param fin 1:without body
 * @return 发送成功的字节数，<0 出错
 */
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request,
                                    xqc_http_headers_t *headers,
                                    uint8_t fin);

/**
 * @param fin 1:没有多余的body需要发送
 * @return 发送成功的字节数，-XQC_EAGAIN下次尝试写, <0 出错
 */
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request,
                                 unsigned char *data,
                                 size_t data_size,
                                 uint8_t fin);

/**
 * @param fin 1:without body
 * @return 用户应该拷贝到自己的内存，NULL 出错
 */
xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request,
                            uint8_t *fin);


/**
 * @param fin 1：body已全部读取完
 * @return 读取到的长度，<0 出错
 */
ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);

/* ************************************************************
 *  transport layer APIs, if you don't need application layer
 *************************************************************/
/**
 * Client connect without http3
 * @param engine return from xqc_engine_create
 * @param user_data For connection
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len
 * @param server_host server domain
 * @param no_crypto_flag 1:without crypto
 * @param conn_ssl_config For handshake
 * @return user should copy cid to your own memory, in case of cid destroyed in xquic library
 */
xqc_cid_t *xqc_connect(xqc_engine_t *engine, void *user_data,
                       xqc_conn_settings_t conn_settings,
                       unsigned char *token, unsigned token_len,
                       char *server_host, int no_crypto_flag,
                       xqc_conn_ssl_config_t *conn_ssl_config,
                       const struct sockaddr *peer_addr,
                       socklen_t peer_addrlen);

/**
 * Send CONNECTION_CLOSE to peer, conn_close_notify will callback when connection destroyed
 * @return 0 for success, <0 for error
 */
int xqc_conn_close(xqc_engine_t *engine, xqc_cid_t *cid);

/**
 * Get errno when conn_close_notify, 0 For no-error
 */
int xqc_conn_get_errno(xqc_connection_t *conn);

/**
 * Server should set user_data when conn_create_notify callbacks
 */
void xqc_conn_set_user_data(xqc_connection_t *conn,
                           void *user_data);

/**
 * Server should get peer addr when conn_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return peer addr
 */
struct sockaddr* xqc_conn_get_peer_addr(xqc_connection_t *conn,
                                       socklen_t *peer_addr_len);

/**
 * Server should get local addr when conn_create_notify callbacks
 * @param local_addr_len is a return value
 * @return local addr
 */
struct sockaddr* xqc_conn_get_local_addr(xqc_connection_t *conn,
                                        socklen_t *local_addr_len);

/**
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
xqc_stream_t* xqc_stream_create (xqc_engine_t *engine,
                                 xqc_cid_t *cid,
                                 void *user_data);

/**
 * Server should set user_data when stream_create_notify callbacks
 */
void xqc_stream_set_user_data(xqc_stream_t *stream,
                              void *user_data);

/**
 * Get connection's user_data by stream
 */
void* xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);

/**
 * Get stream ID
 */
xqc_stream_id_t xqc_stream_id(xqc_stream_t *stream);

/**
 * Send RESET_STREAM to peer, stream_close_notify will callback when stream destroyed
 * @retval 0 for success, <0 for error
 */
int xqc_stream_close (xqc_stream_t *stream);

/**
 * Recv data in stream.
 * @return bytes read, <0 for error
 */
ssize_t xqc_stream_recv (xqc_stream_t *stream,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);

/**
 * Send data in stream.
 * @param fin  0 or 1,  1 - final data block send in this stream.
 * @return bytes sent, -XQC_EAGAIN try next time, <0 for error
 */
ssize_t xqc_stream_send (xqc_stream_t *stream,
                         unsigned char *send_data,
                         size_t send_data_size,
                         uint8_t fin);

/* ************************************************************
 * transport layer APIs end
 *************************************************************/


/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in microsecond
 * @param user_data   connection user_data, server is NULL
 */
int xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time,
                               void *user_data);

/**
 * user should call after a number of packet processed in xqc_engine_packet_process
 */
void xqc_engine_finish_recv (xqc_engine_t *engine);//call after recv loop, may destory connection when error
void xqc_engine_recv_batch (xqc_engine_t *engine, xqc_connection_t *conn);//call after recv a batch packets, do not destory connection

/**
 * Process all connections, user should call when timer expire
 */
void xqc_engine_main_logic (xqc_engine_t *engine);

/**
 * Get dcid and scid before process packet
 */
xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                               unsigned char *buf, size_t size);
xqc_int_t xqc_cid_is_equal(xqc_cid_t *dst, xqc_cid_t *src);
unsigned char* xqc_dcid_str(const xqc_cid_t *cid);
uint8_t xqc_engine_config_get_cid_len(xqc_engine_t *engine);


/**
 * User should call xqc_conn_continue_send when write event ready
 */
int xqc_conn_continue_send(xqc_engine_t *engine,
                           xqc_cid_t *cid);

/**
 * User can get xqc_conn_stats_t by cid
 */
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine,
                                    xqc_cid_t *cid);
#ifdef __cplusplus
}
#endif

#endif /* _XQUIC_H_INCLUDED_ */

