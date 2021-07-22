
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


/* support version for IETF drafts */
#define XQC_SUPPORT_VERSION_MAX         64

typedef enum xqc_proto_version_s {

    XQC_IDRAFT_INIT_VER,            /* placeholder */

    XQC_VERSION_V1,                 /* former version of QUIC RFC */

    XQC_IDRAFT_VER_29,              /* IETF Draft-29 */

    XQC_IDRAFT_VER_NEGOTIATION,     /* Special version for version negotiation. */

    XQC_VERSION_MAX
} xqc_proto_version_t;


#define XQC_TLS_CIPHERS "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
#define XQC_TLS_GROUPS "P-256:X25519:P-384:P-521"
#define XQC_TLS_AEAD_OVERHEAD_MAX_LEN   16

#define XQC_MAX_SEND_MSG_ONCE           32

#define XQC_SOCKET_ERROR                -1
#define XQC_SOCKET_EAGAIN               -2

typedef enum {
    XQC_REQ_NOTIFY_READ_HEADER  = 1 << 0,
    XQC_REQ_NOTIFY_READ_BODY    = 1 << 1,
} xqc_request_notify_flag_t;

typedef void (*xqc_set_event_timer_pt)(xqc_usec_t wake_after, void *engine_user_data);

typedef void (*xqc_save_token_pt)(const unsigned char *token, uint32_t token_len, void *conn_user_data);

typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);

/* session save callback */
typedef xqc_save_string_pt xqc_save_session_pt;

/* transport parameters save callback */
typedef xqc_save_string_pt xqc_save_trans_param_pt;

typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data);

typedef void (*xqc_h3_handshake_finished_pt)(xqc_h3_conn_t *h3_conn, void *conn_user_data);

typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *conn_user_data);

typedef void (*xqc_h3_conn_ping_ack_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *ping_user_data, void *conn_user_data);



/**
 * write socket
 * @param conn_user_data user_data of connection
 * @param buf  packet buffer
 * @param size  packet size
 * @param peer_addr  peer address
 * @param peer_addrlen  peer address length
 * @return bytes of data which is successfully sent to socket:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket write event is ready
 * Warning: server's user_data is what we passed in xqc_engine_packet_process when send a reset packet
 */
typedef ssize_t (*xqc_socket_write_pt)(const unsigned char *buf, size_t size,
                                       const struct sockaddr *peer_addr,
                                       socklen_t peer_addrlen, void *conn_user_data);
typedef ssize_t (*xqc_send_mmsg_pt)(const struct iovec *msg_iov, unsigned int vlen,
                                        const struct sockaddr *peer_addr,
                                        socklen_t peer_addrlen, void *conn_user_data);

/**
 * for multi-path write socket
 * @param path_id  path identifier
 * @param conn_user_data user_data of connection
 * @param buf  packet buffer
 * @param size  packet size
 * @param peer_addr  peer address
 * @param peer_addrlen  peer address length
 * @return bytes of data which is successfully sent to socket:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket write event is ready
 * Warning: server's user_data is what we passed in xqc_engine_packet_process when send a reset packet
 */
typedef ssize_t (*xqc_mp_socket_write_pt)(uint64_t path_id,
    const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
typedef ssize_t (*xqc_mp_send_mmsg_pt)(uint64_t path_id,
    const struct iovec *msg_iov, unsigned int vlen, const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);

typedef void (*xqc_conn_ready_to_create_path_notify_pt)(const xqc_cid_t *scid, void *conn_user_data);
typedef void (*xqc_path_created_notify_pt)(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data);
typedef void (*xqc_path_removed_notify_pt)(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data);

/**
 * client certificate verify callback
 * @param certs[] X509 certificates in DER format
 * @param cert_len[] lengths of X509 certificates in DER format
 * @return 0 for success, -1 for verify failed and xquic will close the connection 
 */
typedef int (*xqc_cert_verify_pt)(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *conn_user_data);

/**
 * for server, custom cid generate handler,
 * @param cid_buf  buffer for cid generated
 * @param cid_buflen len for cid_buf
 * @param engine_user_data  user data of engine from `xqc_engine_create`
 * @return  negative for failed , non-negative (0 contians ) for the length of bytes written
 * if the length of bytes written shorter than cid_buflen , xquic will fill rest of them with random bytes
 * */
typedef ssize_t (*xqc_cid_generate_pt)(uint8_t *cid_buf, size_t cid_buflen, void *engine_user_data);


/**
 * keylog callback
 */
typedef void (*xqc_keylog_pt)(const char *line, void *engine_user_data);


/*
 * Callbacks below return -1 for fatal error, e.g. malloc fail, xquic will close the connection, return 0 otherwise
 */
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data);
typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data);
typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *strm_user_data);
typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *strm_user_data);
typedef int (*xqc_h3_request_read_notify_pt)(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *strm_user_data);
/* user_data is the parameter of xqc_engine_packet_process */
typedef int (*xqc_server_accept_pt)(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data);


/* log interface */
#define XQC_MAX_LOG_LEN 2048
typedef struct xqc_log_callbacks_s {
    void (*xqc_log_write_err)(const void *buf, size_t size, void *engine_user_data);
    void (*xqc_log_write_stat)(const void *buf, size_t size, void *engine_user_data);
} xqc_log_callbacks_t;

/* transport layer */
typedef struct xqc_conn_callbacks_s {
    /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_conn_notify_pt          conn_create_notify;         /* required for server, optional for client */
    /* 连接关闭时回调,用户可以回收资源 */
    xqc_conn_notify_pt          conn_close_notify;
    /* for handshake done */
    xqc_handshake_finished_pt   conn_handshake_finished;    /* optional */
    /* ping is acked */
    xqc_conn_ping_ack_notify_pt conn_ping_acked;            /* optional */
} xqc_conn_callbacks_t;

/* application layer */
typedef struct xqc_h3_conn_callbacks_s {
    /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_h3_conn_notify_pt          h3_conn_create_notify;       /* required for server, optional for client */
    /* 连接关闭时回调,用户可以回收资源 */
    xqc_h3_conn_notify_pt          h3_conn_close_notify;
    /* for handshake done */
    xqc_h3_handshake_finished_pt   h3_conn_handshake_finished;  /* optional */
    /* ping is acked */
    xqc_h3_conn_ping_ack_notify_pt h3_conn_ping_acked;          /* optional */
} xqc_h3_conn_callbacks_t;

/* transport layer */
typedef struct xqc_stream_callbacks_s {
    xqc_stream_notify_pt        stream_read_notify;     /* 可读时回调，用户可以继续调用读接口 */
    xqc_stream_notify_pt        stream_write_notify;    /* 可写时回调，用户可以继续调用写接口 */
    xqc_stream_notify_pt        stream_create_notify;   /* required for server, optional for client，
                                                         * 请求创建完成后回调，用户可以创建自己的请求上下文 */
    xqc_stream_notify_pt        stream_close_notify;    /* 关闭时回调，用户可以回收资源 */
} xqc_stream_callbacks_t;

/* application layer */
typedef struct xqc_h3_request_callbacks_s {
    xqc_h3_request_read_notify_pt   h3_request_read_notify;     /* 可读时回调，用户可以继续调用读接口，读headers或body */
    xqc_h3_request_notify_pt        h3_request_write_notify;    /* 可写时回调，用户可以继续调用写接口,写headers或body */
    xqc_h3_request_notify_pt        h3_request_create_notify;   /* required for server, optional for client，
                                                                 * 请求创建完成后回调，用户可以创建自己的请求上下文 */
    xqc_h3_request_notify_pt        h3_request_close_notify;    /* 关闭时回调，用户可以回收资源 */
} xqc_h3_request_callbacks_t;

typedef struct xqc_cc_params_s {
    uint32_t    customize_on;
    uint32_t    init_cwnd;
    uint32_t    expect_bw;
    uint32_t    max_expect_bw;
    uint32_t    cc_optimization_flags;
} xqc_cc_params_t;

typedef struct xqc_congestion_control_callback_s {
    /* 初始化时回调，用于分配内存 */
    size_t (*xqc_cong_ctl_size) (void);
    /* 连接初始化时回调，支持传入拥塞算法参数 */
    void (*xqc_cong_ctl_init) (void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params);
    /* 核心回调，检测到丢包时回调，按照算法策略降低拥塞窗口 */
    void (*xqc_cong_ctl_on_lost) (void *cong_ctl, xqc_usec_t lost_sent_time);
    /* 核心回调，报文被ack时回调，按照算法策略增加拥塞窗口 */
    void (*xqc_cong_ctl_on_ack) (void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now);
    /* 发包时回调，用于判断包是否能发送 */
    uint64_t (*xqc_cong_ctl_get_cwnd) (void *cong_ctl);
    /* 检测到一个RTT内所有包都丢失时回调，重置拥塞窗口 */
    void (*xqc_cong_ctl_reset_cwnd) (void *cong_ctl);
    /* 判断是否在慢启动阶段 */
    int (*xqc_cong_ctl_in_slow_start) (void *cong_ctl);

    /* If the connection is in recovery state. */
    int (*xqc_cong_ctl_in_recovery) (void *cong_ctl);

    /* This function is used by BBR and Cubic*/
    void (*xqc_cong_ctl_restart_from_idle) (void *cong_ctl, uint64_t arg);

    /* For BBR */
    void (*xqc_cong_ctl_bbr) (void *cong_ctl, xqc_sample_t *sampler);
    void (*xqc_cong_ctl_init_bbr) (void *cong_ctl, xqc_sample_t *sampler, xqc_cc_params_t cc_params);
    uint32_t (*xqc_cong_ctl_get_pacing_rate) (void *cong_ctl);
    uint32_t (*xqc_cong_ctl_get_bandwidth_estimate) (void *cong_ctl);

    xqc_bbr_info_interface_t *xqc_cong_ctl_info_cb;
} xqc_cong_ctrl_callback_t;

#ifndef XQC_DISABLE_RENO
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_reno_cb;
#endif
#ifdef XQC_ENABLE_BBR2
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_bbr2_cb;
#endif
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_bbr_cb;
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_cubic_kernel_cb;


/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {
    xqc_log_level_t cfg_log_level;
    xqc_flag_t      cfg_log_timestamp;
    size_t          conn_pool_size;
    size_t          streams_hash_bucket_size;
    size_t          conns_hash_bucket_size;
    size_t          conns_active_pq_capacity;
    size_t          conns_wakeup_pq_capacity;
    uint32_t        support_version_list[XQC_SUPPORT_VERSION_MAX];/* 支持的版本列表 */
    uint32_t        support_version_count;                        /* 版本列表数量 */
    uint8_t         cid_len;
    uint8_t         cid_negotiate; /* just for server, default:0 */
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
    xqc_set_event_timer_pt      set_event_timer;/* 设置定时器回调，定时器到期时用户需要调用xqc_engine_main_logic */

    /* for socket write */
    xqc_socket_write_pt         write_socket;   /* 用户实现socket写接口 */

    /* for send_mmsg write*/
    xqc_send_mmsg_pt            write_mmsg;     /* 批量发送接口 */

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
    xqc_save_session_pt         save_session_cb;

    /* for client, save transport parameter data, Use the domain as the key to save */
    xqc_save_trans_param_pt     save_tp_cb;

    /* for client , verify certificate */
    xqc_cert_verify_pt          cert_verify_cb;

    /* for server, custom cid generator */
    xqc_cid_generate_pt         cid_generate_cb;

    /* for multi-path */
    xqc_conn_ready_to_create_path_notify_pt  ready_to_create_path_notify;
    xqc_path_created_notify_pt               path_created_notify;

    /* keylog */
    xqc_keylog_pt               keylog_cb;
} xqc_engine_callback_t;

#define XQC_ALPN_HTTP3      "h3-29"
#define XQC_ALPN_TRANSPORT  "transport"

typedef struct xqc_engine_ssl_config_s {
    char       *private_key_file;           /* For server */
    char       *cert_file;                  /* For server */
    char       *ciphers;
    char       *groups;
    uint32_t   session_timeout;             /* Session lifetime in second */
    char       *session_ticket_key_data;    /* For server */
    size_t     session_ticket_key_len;      /* For server */

    char       *alpn_list;                  /* For server */
    int        alpn_list_len;               /* For server */
} xqc_engine_ssl_config_t;

typedef struct xqc_conn_ssl_config_s {
    char       *session_ticket_data;             /* For client, client should Use the domain as the key to save */
    size_t      session_ticket_len;              /* For client */
    char       *transport_parameter_data;        /* For client, client should Use the domain as the key to save */
    size_t      transport_parameter_data_len;    /* For client */
    uint8_t     cert_verify_flag;                /* For client certificate verify flag, now only boringssl lib support cert_verify_flag */
} xqc_conn_ssl_config_t;


typedef struct xqc_http_header_s {
    struct iovec        name;
    struct iovec        value;
    uint8_t             flags;          /* 1:do not compress this header */
} xqc_http_header_t;

typedef struct xqc_http_headers_s {
    xqc_http_header_t       *headers;
    size_t                  count;
    size_t                  capacity;   /* User does't care */
} xqc_http_headers_t;

typedef struct xqc_conn_settings_s {
    int                         pacing_on;          /* default: 0 */
    int                         ping_on;            /* client sends PING to keepalive, default:0 */
    xqc_cong_ctrl_callback_t    cong_ctrl_callback; /* default: xqc_cubic_cb */
    xqc_cc_params_t             cc_params;
    uint32_t                    so_sndbuf;          /* socket option SO_SNDBUF, 0 for unlimited */
    xqc_proto_version_t         proto_version;      /* QUIC protocol version */
    uint32_t                    idle_time_out;      /* idle timeout interval */
    uint64_t                    enable_multipath;   /* default: 0 */
    int32_t                     spurious_loss_detect_on;
} xqc_conn_settings_t;

typedef struct xqc_h3_conn_settings_s {
    uint64_t max_field_section_size;
    uint64_t max_pushes;
    uint64_t qpack_max_table_capacity;
    uint64_t qpack_blocked_streams;
} xqc_h3_conn_settings_t;

typedef enum {
    XQC_0RTT_NONE,      /* without 0RTT */
    XQC_0RTT_ACCEPT,
    XQC_0RTT_REJECT,
} xqc_0rtt_flag_t;

typedef struct xqc_conn_stats_s {
    uint32_t    send_count;
    uint32_t    lost_count;
    uint32_t    tlp_count;
    uint32_t    spurious_loss_count;
    xqc_usec_t  srtt;
    xqc_0rtt_flag_t    early_data_flag;
    uint32_t    recv_count;
    int         enable_multipath;
    int         spurious_loss_detect_on;
    int         conn_err;
    char        ack_info[50];
} xqc_conn_stats_t;

typedef struct xqc_request_stats_s {
    size_t      send_body_size;
    size_t      recv_body_size;
    size_t      send_header_size;   /* compressed header size */
    size_t      recv_header_size;   /* compressed header size */
    int         stream_err;         /* 0 For no-error */
} xqc_request_stats_t;

typedef xqc_usec_t (*xqc_timestamp_pt)(void);

extern xqc_timestamp_pt xqc_realtime_timestamp;  //获取现实世界的时间戳。
extern xqc_timestamp_pt xqc_monotonic_timestamp; //获取单调递增的时间戳。

/**
 * Modify engine config before engine created. Default config will be used otherwise.
 * Item value 0 means use default value.
 * @return 0 for success, <0 for error. default value is used if config item is illegal
 */
xqc_int_t xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config);


/**
 * For server, it can be called anytime. settings will take effect on new connections
 */
void xqc_server_set_conn_settings(const xqc_conn_settings_t *settings);

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
XQC_EXPORT_PUBLIC_API
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
    const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config,
    const xqc_engine_callback_t *engine_callback,
    void *user_data);

XQC_EXPORT_PUBLIC_API
void xqc_engine_destroy(xqc_engine_t *engine);

/**
 * Set engine log level, call after engine is created
 * @param log_level engine will print logs which level >= log_level
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level);


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
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, void *user_data,
                          const xqc_conn_settings_t *conn_settings,
                          const unsigned char *token, unsigned token_len,
                          const char *server_host, int no_crypto_flag,
                          const xqc_conn_ssl_config_t *conn_ssl_config,
                          const struct sockaddr *peer_addr,
                          socklen_t peer_addrlen);

XQC_EXPORT_PUBLIC_API
int xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * Return quic_connection on which h3_conn rely
 * @param h3_conn http3 connection
 */
XQC_EXPORT_PUBLIC_API
xqc_connection_t *  xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3_conn);

/**
 * Get errno when h3_conn_close_notify, HTTP_NO_ERROR(0x100) For no-error
 */
XQC_EXPORT_PUBLIC_API
int xqc_h3_conn_get_errno(xqc_h3_conn_t *h3_conn);

/**
 * Server should set user_data when h3_conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3_conn,
                               void *user_data);

/**
 * User can set h3 settings when h3_conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_conn_set_settings(xqc_h3_conn_t *h3_conn,
    const xqc_h3_conn_settings_t *h3_conn_settings);

/**
 * Server should get peer addr when h3_conn_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return peer addr
 */
XQC_EXPORT_PUBLIC_API
struct sockaddr* xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3_conn,
                                           socklen_t *peer_addr_len);

/**
 * Server should get local addr when h3_conn_create_notify callbacks
 * @param local_addr_len is a return value
 * @return local addr
 */
XQC_EXPORT_PUBLIC_API
struct sockaddr* xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3_conn,
                                           socklen_t *local_addr_len);

/**
 * Send PING to peer, if ack received, h3_conn_ping_acked will callback with user_data
 * @return 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
int xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);


/**
 * @return 1 for can send 0rtt, 0 for cannot send 0rtt
 */
XQC_EXPORT_PUBLIC_API
int xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3_conn);

/**
 * @param user_data For request
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine,
                                        const xqc_cid_t *cid,
                                        void *user_data);

/**
 * User can get xqc_request_stats_t before request destroyed
 */
XQC_EXPORT_PUBLIC_API
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);

/**
 * Server should set user_data when h3_request_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request,
                                  void *user_data);

/**
 * Get connection's user_data by request
 */
XQC_EXPORT_PUBLIC_API
void* xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);

/**
 * Get stream ID by request
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);

/**
 * Send RESET_STREAM to peer, h3_request_close_notify will callback when request destroyed
 * @retval 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
int xqc_h3_request_close (xqc_h3_request_t *h3_request);

/**
 * @param fin 1:without body
 * @return Bytes sent，<0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request,
                                    xqc_http_headers_t *headers,
                                    uint8_t fin);

/**
 * @param fin 1:Request finish
 * @return Bytes sent，-XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request,
                                 unsigned char *data,
                                 size_t data_size,
                                 uint8_t fin);

/**
 * @param fin 1:without body
 * @return user should copy headers to your own memory，NULL for error
 */
XQC_EXPORT_PUBLIC_API
xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request,
                            uint8_t *fin);


/**
 * @param fin 1:Request finished
 * @return Bytes read，-XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);


/**
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_dec_max_dtable_capacity(xqc_engine_t *engine, uint64_t value);

/**
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_enc_max_dtable_capacity(xqc_engine_t *engine, uint64_t value);


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
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_connect(xqc_engine_t *engine, void *user_data,
    const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len,
    const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen);

/**
 * Send CONNECTION_CLOSE to peer, conn_close_notify will callback when connection destroyed
 * @return 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
int xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * Get errno when conn_close_notify, 0 For no-error
 */
XQC_EXPORT_PUBLIC_API
int xqc_conn_get_errno(xqc_connection_t *conn);

/**
 * Server should set user_data when conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_user_data(xqc_connection_t *conn,
                           void *user_data);

/**
 * Server should get peer addr when conn_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return peer addr
 */
XQC_EXPORT_PUBLIC_API
struct sockaddr* xqc_conn_get_peer_addr(xqc_connection_t *conn,
                                       socklen_t *peer_addr_len);

/**
 * Server should get local addr when conn_create_notify callbacks
 * @param local_addr_len is a return value
 * @return local addr
 */
XQC_EXPORT_PUBLIC_API
struct sockaddr* xqc_conn_get_local_addr(xqc_connection_t *conn,
                                        socklen_t *local_addr_len);

/**
 * Send PING to peer, if ack received, conn_ping_acked will callback with user_data
 * @return 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
int xqc_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);

/**
 * @return 1 for can send 0rtt, 0 for cannot send 0rtt
 */
XQC_EXPORT_PUBLIC_API
int xqc_conn_is_ready_to_send_early_data(xqc_connection_t * conn);

/**
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_t* xqc_stream_create (xqc_engine_t *engine,
                                 const xqc_cid_t *cid,
                                 void *user_data);

/**
 * Server should set user_data when stream_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_stream_set_user_data(xqc_stream_t *stream,
                              void *user_data);

/**
 * Get connection's user_data by stream
 */
XQC_EXPORT_PUBLIC_API
void* xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);

/**
 * Get stream ID
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_stream_id(xqc_stream_t *stream);

/**
 * Send RESET_STREAM to peer, stream_close_notify will callback when stream destroyed
 * @retval 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
int xqc_stream_close (xqc_stream_t *stream);

/**
 * Recv data in stream.
 * @return bytes read, -XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_stream_recv (xqc_stream_t *stream,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);

/**
 * Send data in stream.
 * @param fin  0 or 1,  1 - final data block send in this stream.
 * @return bytes sent, -XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
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
XQC_EXPORT_PUBLIC_API
int xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_usec_t recv_time,
                               void *user_data);

/**
 * user should call after a number of packet processed in xqc_engine_packet_process
 * call after recv a batch packets, may destory connection when error
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_finish_recv (xqc_engine_t *engine);

/**
 * call after recv a batch packets, do not destory connection
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_recv_batch (xqc_engine_t *engine, xqc_connection_t *conn);

/**
 * Process all connections, user should call when timer expire
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_main_logic (xqc_engine_t *engine);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type);


/**
 * Get dcid and scid before process packet
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                               const unsigned char *buf, size_t size);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src);

/**
 * Get scid in hex, end with '\0'
 * @param scid is returned from xqc_connect or xqc_h3_connect
 * @return user should copy return buffer to your own memory if you will access in the future
 */
XQC_EXPORT_PUBLIC_API
unsigned char* xqc_scid_str(const xqc_cid_t *scid);

XQC_EXPORT_PUBLIC_API
unsigned char* xqc_dcid_str(const xqc_cid_t *dcid);

XQC_EXPORT_PUBLIC_API
unsigned char* xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid);

XQC_EXPORT_PUBLIC_API
uint8_t xqc_engine_config_get_cid_len(xqc_engine_t *engine);


/**
 * User should call xqc_conn_continue_send when write event ready
 */
XQC_EXPORT_PUBLIC_API
int xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * User can get xqc_conn_stats_t by cid
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * create new path for client
 * @param cid scid for connection
 * @param new_path_id if new path is created successfully, return new_path_id in this param
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_create_path(xqc_engine_t *engine,
    const xqc_cid_t *cid, uint64_t *new_path_id);


/**
 * Close a path
 * @param cid scid for connection
 * @param close_path_id path identifier for the closing path
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_close_path(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t closed_path_id);



#ifdef __cplusplus
}
#endif

#endif /* _XQUIC_H_INCLUDED_ */

