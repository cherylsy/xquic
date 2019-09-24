#ifndef _XQC_CLIENT_H_INCLUDED_
#define _XQC_CLIENT_H_INCLUDED_

#include "include/xquic_typedef.h"

xqc_connection_t *xqc_client_connect(xqc_engine_t *engine, void *user_data,
                                     unsigned char *token, unsigned token_len,
                                     char *server_host, int no_crypto_flag,
                                     xqc_conn_ssl_config_t *conn_ssl_config);

xqc_connection_t * xqc_client_create_connection(xqc_engine_t *engine,
                                                xqc_cid_t dcid, xqc_cid_t scid,
                                                xqc_conn_callbacks_t *callbacks,
                                                xqc_conn_settings_t *settings,
                                                char * server_host,
                                                int no_crypto_flag,
                                                xqc_conn_ssl_config_t * conn_ssl_config,
                                                void *user_data);

#endif /* _XQC_CLIENT_H_INCLUDED_ */

