#ifndef _XQC_TLS_CB_H_INCLUDED_
#define _XQC_TLS_CB_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/crypto/xqc_tls_public.h"
#include "src/transport/xqc_conn.h"


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


int xqc_update_key(xqc_connection_t *conn, void *user_data );
int xqc_do_update_key(xqc_connection_t *conn);
int xqc_conn_commit_key_update(xqc_connection_t *conn, uint64_t pkt_num) ;

#endif /* _XQC_TLS_CB_H_INCLUDED_ */


