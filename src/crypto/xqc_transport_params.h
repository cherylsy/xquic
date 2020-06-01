#ifndef XQC_TRANSPORT_PARAMS_H_
#define XQC_TRANSPORT_PARAMS_H_

#include <xquic/xquic.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_conn.h"


// 用于释放xqc_serialize_xxx_transport_parames所产生的out参数。
static inline 
void xqc_transport_parames_serialization_free(void *buf) {
    if(buf) {
        xqc_free(buf);
    }
}


int xqc_conn_set_early_remote_transport_params(xqc_connection_t *conn, const xqc_transport_params_t *params);

int xqc_read_transport_params(char * tp_data, size_t tp_data_len, xqc_transport_params_t *params);

/**
 * 序列化客户端的tansport参数。out需要使用xqc_transport_parames_serialization_free释放。
 * return ZERO on success 
 * */
int xqc_serialize_client_transport_params(xqc_connection_t * conn, xqc_transport_params_type_t exttype,const unsigned char **out,size_t *outlen);

/**
 * 在客户端上反序列化收到的对端的transport params。
 * */
int xqc_on_client_recv_peer_transport_params(xqc_connection_t * conn,const unsigned char *inbuf,size_t inlen);

/**
 * 序列化服务端的tansport参数。out需要使用xqc_transport_parames_serialization_free释放。
 * return ZERO on success 
 * */
int xqc_serialize_server_transport_params(xqc_connection_t * conn, xqc_transport_params_type_t exttype,const unsigned char **out,size_t *outlen);

/**
 * 在服务端反序列化收到的对端的transport params。
 * */
int xqc_on_server_recv_peer_transport_params(xqc_connection_t * conn,const unsigned char *inbuf,size_t inlen);

#endif // XQC_TRANSPORT_PARAMS_H_