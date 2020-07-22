#ifndef XQC_TRANSPORT_PARAMS_H_
#define XQC_TRANSPORT_PARAMS_H_

#include <xquic/xquic.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_conn.h"


typedef enum {
    XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID = 0x0000,
    XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT = 0x0001,
    XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
    XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE = 0x0003,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
    XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
    XQC_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
    XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION = 0x000c,
    XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d,
    XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x000e,
    XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x000f,
    XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID = 0x0010,
    XQC_TRANSPORT_PARAM_PROTOCOL_MAX,  /* upper limit of params defined in [Transport] */
    XQC_TRANSPORT_PARAM_NO_CRYPTO = 0x1000,
    XQC_TRANSPORT_PARAM_CUSTOMIZED_MAX,  /* upper limit of params defined by xquic */
} xqc_transport_param_id_t;


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