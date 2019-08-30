#ifndef _XQC_TLS_CB_H_INCLUDED_
#define _XQC_TLS_CB_H_INCLUDED_

#include "include/xquic_typedef.h"
#include "xqc_tls_public.h"
#include "transport/xqc_conn.h"
#define XQC_ALPN_V1 "\x7xquic-1"


typedef enum {
  XQC_ERR_INVALID_ARGUMENT = -701,
  XQC_ERR_UNKNOWN_PKT_TYPE = -702,
  XQC_ERR_NOBUF = -703,
  XQC_ERR_PROTO = -705,
  XQC_ERR_INVALID_STATE = -706,
  XQC_ERR_ACK_FRAME = -707,
  XQC_ERR_STREAM_ID_BLOCKED = -708,
  XQC_ERR_STREAM_IN_USE = -709,
  XQC_ERR_STREAM_DATA_BLOCKED = -710,
  XQC_ERR_FLOW_CONTROL = -711,
  XQC_ERR_STREAM_LIMIT = -713,
  XQC_ERR_FINAL_OFFSET = -714,
  XQC_ERR_CRYPTO = -715,
  XQC_ERR_PKT_NUM_EXHAUSTED = -716,
  XQC_ERR_REQUIRED_TRANSPORT_PARAM = -717,
  XQC_ERR_MALFORMED_TRANSPORT_PARAM = -718,
  XQC_ERR_FRAME_ENCODING = -719,
  XQC_ERR_TLS_DECRYPT = -720,
  XQC_ERR_STREAM_SHUT_WR = -721,
  XQC_ERR_STREAM_NOT_FOUND = -722,
  XQC_ERR_VERSION_NEGOTIATION = -723,
  XQC_ERR_STREAM_STATE = -726,
  XQC_ERR_NOKEY = -727,
  XQC_ERR_EARLY_DATA_REJECTED = -728,
  XQC_ERR_RECV_VERSION_NEGOTIATION = -729,
  XQC_ERR_CLOSING = -730,
  XQC_ERR_DRAINING = -731,
  XQC_ERR_TRANSPORT_PARAM = -734,
  XQC_ERR_DISCARD_PKT = -735,
  XQC_ERR_FATAL = -750,
  XQC_ERR_NOMEM = -751,
  XQC_ERR_CALLBACK_FAILURE = -752,
  XQC_ERR_INTERNAL = -753
} xqc_lib_error;


int xqc_tls_key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen, void *arg);

void xqc_msg_cb(int write_p, int version, int content_type, const void *buf,
        size_t len, SSL *ssl, void *arg);

int xqc_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
        unsigned char *outlen, const unsigned char *in,
        unsigned int inlen, void *arg);

int xqc_server_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg);

int xqc_server_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg);

void xqc_transport_params_free_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *out,
        void *add_arg);

int xqc_client_transport_params_add_cb(SSL *ssl, unsigned int ext_type,
        unsigned int content, const unsigned char **out,
        size_t *outlen, X509 *x, size_t chainidx, int *al,
        void *add_arg);

int xqc_client_transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
        unsigned int context, const unsigned char *in,
        size_t inlen, X509 *x, size_t chainidx, int *al,
        void *parse_arg);

int xqc_read_transport_params(char * tp_data, size_t tp_data_len, xqc_transport_params_t *params);
int xqc_conn_set_early_remote_transport_params(
    xqc_connection_t *conn, const xqc_transport_params_t *params);



int xqc_update_key(xqc_connection_t *conn, void *user_data );
int xqc_do_update_key(xqc_connection_t *conn);
int xqc_conn_commit_key_update(xqc_connection_t *conn, uint64_t pkt_num) ;
#endif /* _XQC_TLS_CB_H_INCLUDED_ */


