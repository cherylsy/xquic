#ifndef __AXQUIC_H__
#define __AXQUIC_H__

#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>
#include "xqc_cmake_config.h"
#include "include/xquic.h"
#include "congestion_control/xqc_new_reno.h"
#include "congestion_control/xqc_cubic.h"
#include "congestion_control/xqc_bbr.h"
#include "include/xquic_typedef.h"
#include "common/xqc_list.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    xqc_set_event_timer_pt      set_event_timer;
    xqc_save_token_pt           save_token;
    xqc_socket_write_pt                 write_socket;
    xqc_conn_callbacks_t        conn_callbacks;
    xqc_stream_callbacks_t      stream_callbacks;
}xquic_callbacks;

typedef struct {
    char    *cipher;
    char    *groups;
    char    *session_ticket_data;
    size_t  session_ticket_len;
    char    *transport_parameter_data;
    size_t  transport_parameter_data_len;

}xquic_client_config_t;


typedef struct axquic_data_buf{
    xqc_list_head_t list_head;
    size_t  buf_len;
    size_t  data_len;
    //size_t  data_left;
    size_t  already_consume;
    uint8_t fin;
    char    data[];

}axquic_data_buf_t;

typedef struct{

    xqc_cid_t               *cid;
    xqc_stream_t            *stream;
    xqc_list_head_t              send_frame_data_buf;

}axquic_client_stream_t;


static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000000 + tv.tv_usec;
    return  ul;
}


xqc_engine_t *  axquic_client_initial_engine(xqc_engine_callback_t callbacks, xqc_conn_settings_t conn_setting, void * user_data);

xqc_engine_t * axquic_server_initial_engine( xqc_engine_callback_t callback, xqc_conn_settings_t conn_settings,
        char * session_ticket_key, int ticket_key_len, char * private_key_file, char * cert_file, void * user_data);

xqc_cid_t * axquic_connect(xqc_engine_t *engine, void * user_data, char * server_addr,
        uint16_t server_port, uint8_t * token, int token_len,
        uint8_t * session_ticket_data, int session_ticket_len,
        uint8_t * transport_parameter_data, int transport_parameter_data_len,
        struct sockaddr *peer_addr, socklen_t peer_addrlen);

axquic_client_stream_t * axquic_open_stream(xqc_engine_t * engine, xqc_cid_t * cid);
int axquic_send_stream_buf(axquic_client_stream_t * client_stream);

int axquic_send_stream_buf(axquic_client_stream_t * client_stream);


int axquic_send(axquic_client_stream_t * client_stream, char * data, int data_len, uint8_t fin);
int axquic_recv(axquic_client_stream_t * client_stream, uint8_t *buffer, size_t len, uint8_t *fin);

int axquic_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time,
                               void *user_data);


#ifdef __cplusplus
}
#endif


#endif


