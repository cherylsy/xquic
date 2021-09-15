#ifndef XQC_H3_H
#define XQC_H3_H

#include "xquic.h"


#ifdef __cplusplus
extern "C" {
#endif


/* connection settings for http3 */
typedef struct xqc_h3_conn_settings_s {
    /* MAX_FIELD_SECTION_SIZE of http3 */
    uint64_t max_field_section_size;

    /* MAX_PUSH_STREAMS */
    uint64_t max_pushes;

    /* MAX_DYNAMIC_TABLE_CAPACITY */
    uint64_t qpack_max_table_capacity;

    /* MAX_BLOCKED_STREAMS */
    uint64_t qpack_blocked_streams;
} xqc_h3_conn_settings_t;



/**
 * @brief init h3 context into xqc_engine_t, this MUST BE called before create any http3 connection
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @return xqc_int_t XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_init(xqc_engine_t *engine);



/**
 * @brief set max h3 max dynamic table capacity
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value capacity of dynamic table, 0 for disable dynamic table 
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_max_dtable_capacity(xqc_engine_t *engine, size_t capacity);

/**
 * @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_dec_max_dtable_capacity(xqc_engine_t *engine, size_t value);

/**
 * @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_enc_max_dtable_capacity(xqc_engine_t *engine, size_t value);

/**
 * @brief set max h3 field section size
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param size size of field section size
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_max_field_section_size(xqc_engine_t *engine, size_t size);



/**
 * @brief create and http3 connection
 * 
 * @param engine return from xqc_engine_create
 * @param conn_settings connection settings
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len length of token
 * @param server_host server domain
 * @param no_crypto_flag 1:without crypto
 * @param conn_ssl_config For handshake
 * @param peer_addr address of peer
 * @param peer_addrlen length of peer_addr
 * @param user_data returned in connection callback functions
 * @return cid of the connection; user should copy cid to your own memory, in case of cid destroyed
 * in xquic library
 */
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);


/**
 * @brief manually close a http3 connection
 * 
 * @param engine engine handler created by xqc_engine_create
 * @param cid connection id of http3 connection
 * @return XQC_OK for success, others for failure 
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * @brief get QUIC connection handleer TODO: 检查是否有用到？
 * 
 * @param h3c http3 connection handler
 * @return quic_connection on which h3_conn rely
 */
XQC_EXPORT_PUBLIC_API
xqc_connection_t *xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3c);

/**
 * @brief get http3 protocol error number
 * 
 * @param h3c handler of http3 connection
 * @return error number of http3 connection, HTTP_NO_ERROR(0x100) For no-error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_errno(xqc_h3_conn_t *h3c);

/**
 * @brief set user_data for http3 connection, 
 * 
 * @param h3c handler of http3 connection
 * @param user_data should set user_data when h3_conn_create_notify callbacks, which will be
 * returned as parameter of http3 connection callback functions
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3c, void *user_data);

/**
 * User can set h3 settings when h3_conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_conn_set_settings(xqc_h3_conn_t *h3c,
    const xqc_h3_conn_settings_t *h3_conn_settings);

/**
 * @brief get peer address information, server should call this when h3_conn_create_notify triggers
 * 
 * @param h3c handler of http3 connection
 * @param addr [out] output address of peer
 * @param peer_addr_len [out] output length of addr
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr,
    socklen_t *peer_addr_len);

/**
 * @brief get local address information, server should call this when h3_conn_create_notify triggers
 * 
 * @param h3c handler of http3 connection
 * @param addr [out] output address of peer
 * @param peer_addr_len [out] output length of addr
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, 
    socklen_t *local_addr_len);

/**
 * @brief Send PING to peer, if ack received, h3_conn_ping_acked will callback with user_data
 * 
 * @param engine handler of engine
 * @param cid connectoin id of http3 connection, which is generated by xqc_h3_connect
 * @param ping_user_data 
 * @return XQC_OK for success, < 0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);

/**
 * @brief check if h3 connection is ready to send 0rtt data
 * @param h3c h3 connection handler
 * @return XQC_TRUE for can send 0rtt, XQC_FALSE for can not
 */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3c);

/**
 * @brief set the dynamic table capacity of an existing h3 connection
 * @param h3c h3 connection handler
 * @param capacity capacity of dynamic table, 0 for disable dynamic table 
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_set_qpack_dtable_cap(xqc_h3_conn_t *h3c, size_t capacity);



/**
 * @brief create a http3 request
 * @param engine handler created by xqc_engine_create
 * @param cid connection id of http3 connection
 * @param user_data For request
 * @return handler of http3 request
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, 
    void *user_data);

/**
 * @brief gete statistics of a http3 request user can get it before request destroyed
 * 
 * @param h3_request handler of http3 request
 * @return statistics information of request
 */
XQC_EXPORT_PUBLIC_API
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);

/**
 * @brief set user_data of a http3 request, which will be used as parameter of request
 * callback functions. server should set user_data when h3_request_create_notify triggers
 * 
 * @param h3_request handler of http3 request
 * @param user_data user data of request callback functions
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data);

/**
 * @brief get connection's user_data by request
 * 
 * @param h3_request handler of http3 request
 * @return user_data set by user
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);

/**
 * @brief Get QUIC stream ID by request
 * 
 * @param h3_request handler of http3 request
 * @return QUIC stream id
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);

/**
 * @brief close request, send QUIC RESET_STREAM frame to peer. h3_request_close_notify will 
 * triggered when request is finally destroyed
 * 
 * @param h3_request handler of http3 request
 * @return XQC_OK for success, others for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_request_close(xqc_h3_request_t *h3_request);

/**
 * @brief send http headers to peer
 * 
 * @param h3_request handler of http3 request
 * @param headers http headers
 * @param fin request finish flag, 1 for finish. if set here, it means request has no body
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finnished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers,
    uint8_t fin);

/**
 * @brief send http body to peer
 * 
 * @param h3_request handler of http3 request
 * @param data content of body
 * @param data_size length of body
 * @param fin request finish flag, 1 for finish.
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finnished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data, 
    size_t data_size, uint8_t fin);

/**
 * @brief receive headers of a request
 * 
 * @param h3_request handler of http3 request
 * @param fin request finish flag, 1 for finish. if not 0, it means request has no body
 * @return request headers. user should copy headers to your own memory，NULL for error
 */
XQC_EXPORT_PUBLIC_API
xqc_http_headers_t *xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin);

/**
 * @brief receive body of a request
 * 
 * @param h3_request handler of http3 request
 * @param fin request finish flag, 1 for finish
 * @return Bytes read，-XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf, 
    size_t recv_buf_size, uint8_t *fin);


#ifdef __cplusplus
}
#endif


#endif
