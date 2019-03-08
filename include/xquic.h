
#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * @file
 * Public API for using libxquic
 */

#include <sys/socket.h>
#include <../transport/xqc_transport.h>

typedef struct xqc_engine_s xqc_engine_t;

/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {

}xqc_config_t;

typedef enum {
    XQC_ENGINE_SERVER,
    XQC_ENGINE_CLIENT
}xqc_engine_type_t;

typedef struct xqc_engine_api {

}xqc_engine_api_t;

typedef struct xqc_packet_s {
    unsigned char *buf;
    size_t         size;
    
    uint64_t       recv_time;  /* millisecond */
}xqc_packet_t;

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *xqc_engine_new (xqc_engine_type_t engine_type);

/**
 * Init engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
void xqc_engine_init_config (xqc_engine_t *engine,
                             xqc_config_t *engine_config, 
                             xqc_engine_type_t engine_type);

/**
 * Set xquic engine API.
 */
void xqc_engine_set_api (xqc_engine_t *engine,
                         xqc_engine_api_t *engine_api);


xqc_connection_t *xqc_engine_connect (xqc_engine_t *engine, 
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen);

/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in millisecond
 */
int xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               uint64_t recv_time);


ssize_t xqc_stream_recv (xqc_connection_t *c,
                         xqc_stream_t *stream,
                         void *recv_buf,
                         size_t recv_buf_size);

ssize_t xqc_stream_send (xqc_connection_t *c,
                         xqc_stream_t *stream,
                         void *send_data,
                         size_t send_data_size,
                         uint8_t fin);


#endif /* _XQUIC_H_INCLUDED_ */

