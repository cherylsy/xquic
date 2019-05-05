#ifndef _XQC_TLS_CB_H_INCLUDED_
#define _XQC_TLS_CB_H_INCLUDED_

#include "include/xquic_typedef.h"

#define XQC_ALPN_D17 "\x5hq-17"


typedef enum {
  XQC_ERR_INVALID_ARGUMENT = -201,
  XQC_ERR_UNKNOWN_PKT_TYPE = -202,
  XQC_ERR_NOBUF = -203,
  XQC_ERR_PROTO = -205,
  XQC_ERR_INVALID_STATE = -206,
  XQC_ERR_ACK_FRAME = -207,
  XQC_ERR_STREAM_ID_BLOCKED = -208,
  XQC_ERR_STREAM_IN_USE = -209,
  XQC_ERR_STREAM_DATA_BLOCKED = -210,
  XQC_ERR_FLOW_CONTROL = -211,
  XQC_ERR_STREAM_LIMIT = -213,
  XQC_ERR_FINAL_OFFSET = -214,
  XQC_ERR_CRYPTO = -215,
  XQC_ERR_PKT_NUM_EXHAUSTED = -216,
  XQC_ERR_REQUIRED_TRANSPORT_PARAM = -217,
  XQC_ERR_MALFORMED_TRANSPORT_PARAM = -218,
  XQC_ERR_FRAME_ENCODING = -219,
  XQC_ERR_TLS_DECRYPT = -220,
  XQC_ERR_STREAM_SHUT_WR = -221,
  XQC_ERR_STREAM_NOT_FOUND = -222,
  XQC_ERR_VERSION_NEGOTIATION = -223,
  XQC_ERR_STREAM_STATE = -226,
  XQC_ERR_NOKEY = -227,
  XQC_ERR_EARLY_DATA_REJECTED = -228,
  XQC_ERR_RECV_VERSION_NEGOTIATION = -229,
  XQC_ERR_CLOSING = -230,
  XQC_ERR_DRAINING = -231,
  XQC_ERR_TRANSPORT_PARAM = -234,
  XQC_ERR_DISCARD_PKT = -235,
  XQC_ERR_FATAL = -500,
  XQC_ERR_NOMEM = -501,
  XQC_ERR_CALLBACK_FAILURE = -502,
  XQC_ERR_INTERNAL = -503
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


#endif /* _XQC_TLS_CB_H_INCLUDED_ */


