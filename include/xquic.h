
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

#define XQC_TLS_CIPHERS "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
#define XQC_TLS_GROUPS "P-256:X25519:P-384:P-521"

#define XQC_TLS_AEAD_OVERHEAD_MAX_LEN 16

typedef void (*xqc_set_event_timer_pt)(void *timer, xqc_msec_t wake_after);

typedef void (*xqc_save_token_pt)(const unsigned char *token, uint32_t token_len);

typedef ssize_t (*xqc_send_pt)(void *user, unsigned char *buf, size_t size);

typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, void *user_data);

typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *conn, void *user_data);

typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *user_data);

typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *user_data);

typedef int (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *user_data);

//session save callback
typedef int  (*xqc_save_session_cb_t )(char * data, size_t data_len, char * user_data);
typedef int  (*xqc_save_tp_cb_t )(char * data, size_t data_len, char * user_data) ;

/* transport layer */
struct xqc_conn_callbacks_s {
    xqc_conn_notify_pt          conn_create_notify; /* optional 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_conn_notify_pt          conn_close_notify; /* optional 连接关闭时回调,用户可以回收资源 */

    /* for handshake done */
    //xqc_handshake_finished_pt   conn_handshake_finished;  /* optional */
};

/* application layer */
struct xqc_h3_conn_callbacks_s {
    xqc_h3_conn_notify_pt          h3_conn_create_notify; /* optional 连接创建完成后回调,用户可以创建自己的连接上下文 */
    xqc_h3_conn_notify_pt          h3_conn_close_notify; /* optional 连接关闭时回调,用户可以回收资源 */
};

/* transport layer */
typedef struct xqc_stream_callbacks_s {
    xqc_stream_notify_pt        stream_read_notify; /* 可读时回调，用户可以继续调用读接口 */
    xqc_stream_notify_pt        stream_write_notify; /* 可写时回调，用户可以继续调用写接口 */
    xqc_stream_notify_pt        stream_close;   /* optional 关闭时回调，用户可以回收资源 */
} xqc_stream_callbacks_t;

/* application layer */
typedef struct xqc_h3_request_callbacks_s {
    xqc_h3_request_notify_pt    h3_request_read_notify; /* 可读时回调，用户可以继续调用读接口，读headers或body */
    xqc_h3_request_notify_pt    h3_request_write_notify; /* 可写时回调，用户可以继续调用写接口,写headers或body */
    xqc_h3_request_notify_pt    h3_request_create; /* optional 服务端使用，请求创建完成后回调，用户可以创建自己的请求上下文 */
    xqc_h3_request_notify_pt    h3_request_close; /* optional 关闭时回调，用户可以回收资源 */
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

    /* for event loop */
    xqc_set_event_timer_pt      set_event_timer; /* 设置定时器回调，定时器到期时用户需要调用xqc_engine_main_logic */

    xqc_save_token_pt           save_token; /* 保存token到本地，connect时带上token */

    /* for socket write */
    xqc_send_pt                 write_socket; /* 用户实现socket写接口 */

    /* for connection notify */
    xqc_conn_callbacks_t        conn_callbacks;

    /* for h3 connection notify */
    xqc_h3_conn_callbacks_t     h3_conn_callbacks;

    /* for stream notify */
    xqc_stream_callbacks_t      stream_callbacks;

    /* for request notify */
    xqc_h3_request_callbacks_t  h3_request_callbacks;

}xqc_engine_callback_t;


struct xqc_engine_ssl_config {
    char       *private_key_file;
    char       *cert_file;
    char       *ciphers;
    char       *groups;
    //uint32_t   timeout;
    char       *session_ticket_key_data;
    size_t     session_ticket_key_len;

    char       *alpn_list;
    int        alpn_list_len;
};

struct xqc_conn_ssl_config {
    char       *session_ticket_data;
    size_t     session_ticket_len;
    char       *transport_parameter_data;
    size_t     transport_parameter_data_len;
};

typedef struct {
    size_t                      size;
    uint8_t                     name[16];
    uint8_t                     hmac_key[32];
    uint8_t                     aes_key[32];
} xqc_ssl_session_ticket_key_t;

typedef struct xqc_engine_ssl_config xqc_engine_ssl_config_t;
typedef struct xqc_conn_ssl_config  xqc_conn_ssl_config_t;

typedef struct xqc_http_header_s {
    struct iovec        name;
    struct iovec        value;
} xqc_http_header_t;

typedef struct xqc_http_headers_s {
    xqc_http_header_t       *headers;
    size_t                  count;
} xqc_http_headers_t;

struct xqc_conn_settings_s {
    int     pacing_on;
    int     h3;
};

typedef enum {
    XQC_ENG_FLAG_RUNNING    = 1 << 0,
} xqc_engine_flag_t;

typedef struct xqc_engine_s {
    xqc_engine_type_t       eng_type;

    xqc_engine_callback_t   eng_callback;
    xqc_config_t           *config;
    xqc_str_hash_table_t   *conns_hash; /*scid*/
    xqc_str_hash_table_t   *conns_hash_dcid; /*For reset packet*/
    xqc_pq_t               *conns_active_pq; /* In process */
    xqc_wakeup_pq_t        *conns_wait_wakeup_pq; /* Need wakeup after next tick time */

    xqc_conn_settings_t    conn_settings;

    xqc_log_t              *log;
    xqc_random_generator_t *rand_generator;

    void                   *user_data;

    SSL_CTX                *ssl_ctx;  //for ssl
    xqc_engine_ssl_config_t       ssl_config; //ssl config, such as cipher suit, cert file path etc.
    xqc_ssl_session_ticket_key_t  session_ticket_key;

    xqc_engine_flag_t       engine_flag;
}xqc_engine_t;



/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
                                xqc_engine_ssl_config_t * xc_config);

void xqc_engine_destroy(xqc_engine_t *engine);


/**
 * Init engine after engine created.
 */
void
xqc_engine_init (xqc_engine_t *engine,
                 xqc_engine_callback_t engine_callback,
                 xqc_conn_settings_t conn_settings,
                 void *user_data);


/**
 * Client connect with http3
 * @param engine return from xqc_engine_create
 * @param user_data For connection
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len
 * @param server_host server domain
 * @param no_crypto_flag 1:without crypto
 * @param conn_ssl_config For handshake
 * @return
 */
xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, void *user_data,
                          unsigned char *token, unsigned token_len,
                          char *server_host, int no_crypto_flag,
                          xqc_conn_ssl_config_t *conn_ssl_config);

int xqc_h3_conn_close(xqc_engine_t *engine, xqc_cid_t *cid);

xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine,
                                        xqc_cid_t *cid,
                                        void *user_data);

/**
 * Server should set user_data when h3_request_create callbacks
 */
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request,
                                  void *user_data);

/**
 * @param fin 1:without body
 * @return 发送成功的字节数，<0 出错
 */
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request,
                                    xqc_http_headers_t *headers,
                                    uint8_t fin);

/**
 * @param fin 1:没有多余的body需要发送
 * @return 发送成功的字节数，<0 出错
 */
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request,
                                 unsigned char *data,
                                 size_t data_size,
                                 uint8_t fin);

/**
 * @param fin 1:without body
 * @return 用户应该拷贝到自己的内存
 */
xqc_http_headers_t *
xqc_h3_request_recv_header(xqc_h3_request_t *h3_request,
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

/*
 *  transport layer APIs, if you don't need application layer
 */
xqc_cid_t *xqc_connect(xqc_engine_t *engine, void *user_data,
                       unsigned char *token, unsigned token_len,
                       char *server_host, int no_crypto_flag,
                       xqc_conn_ssl_config_t *conn_ssl_config);

int xqc_conn_close(xqc_engine_t *engine, xqc_cid_t *cid);

/**
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
xqc_stream_t* xqc_stream_create (xqc_engine_t *engine,
                                 xqc_cid_t *cid,
                                 void *user_data);

/**
 * Close stream.
 * @retval XQC_OK or XQC_ERROR
 */
/*int xqc_stream_close (xqc_engine_t *engine,
                     xqc_cid_t *cid,
                     uint64_t stream_id);*/

/**
 * Recv data in stream.
 * @return bytes read, -1 for error
 */
ssize_t xqc_stream_recv (xqc_stream_t *stream,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin);

/**
 * Send data in stream.
 * @param fin  0 or 1,  1 - final data block send in this stream.
 * @return bytes sent, -1 for error
 */
ssize_t xqc_stream_send (xqc_stream_t *stream,
                         unsigned char *send_data,
                         size_t send_data_size,
                         uint8_t fin);

/*
 * transport layer APIs end
 */


/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in microsecond
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
void xqc_engine_finish_recv (xqc_engine_t *engine);

/**
 * Process all connections, user should call when timer expire
 */
void xqc_engine_main_logic (xqc_engine_t *engine);


/**
 * User should call xqc_conn_continue_send when write event ready
 */
int xqc_conn_continue_send(xqc_engine_t *engine,
                           xqc_cid_t *cid);


int xqc_set_save_tp_cb(xqc_engine_t *engine,
                       xqc_cid_t * cid,
                       xqc_save_tp_cb_t  cb,
                       void * user_data);

int xqc_set_save_session_cb(xqc_engine_t  *engine,
                            xqc_cid_t *cid,
                            xqc_save_session_cb_t  cb,
                            void * user_data);


#endif /* _XQUIC_H_INCLUDED_ */

