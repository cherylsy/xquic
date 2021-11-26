#ifndef XQC_TLS_CTX_H
#define XQC_TLS_CTX_H

#include "xqc_tls.h"
#include "xqc_tls_common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>


SSL_CTX * xqc_tls_ctx_get_ssl_ctx(xqc_tls_ctx_t *ctx);
xqc_tls_type_t xqc_tls_ctx_get_type(xqc_tls_ctx_t *ctx);


/**
 * @brief get callback functions registered by upper layer
 */
void xqc_tls_ctx_get_tls_callbacks(xqc_tls_ctx_t *ctx, xqc_tls_callbacks_t **tls_cbs);
void xqc_tls_ctx_get_session_ticket_key(xqc_tls_ctx_t *ctx, xqc_ssl_session_ticket_key_t **stk);
void xqc_tls_ctx_get_cfg(xqc_tls_ctx_t *ctx, xqc_engine_ssl_config_t **cfg);
void xqc_tls_ctx_set_keylog_callbacks(xqc_tls_ctx_t *ctx, xqc_keylog_pt keylog_cb);
void xqc_tls_ctx_get_alpn_list(xqc_tls_ctx_t *ctx, unsigned char **alpn_list, size_t *alpn_list_len);

#endif
