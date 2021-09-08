#include "xqc_hq.h"

#define XQC_ALPN_HQ_INTEROP "hq-interop"
#define XQC_ALPN_HQ_29      "hq-29"


const char* const xqc_hq_alpn[] = {
    [XQC_IDRAFT_INIT_VER]        = "",     /* placeholder */
    [XQC_VERSION_V1]             = XQC_ALPN_HQ_INTEROP,     /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = XQC_ALPN_HQ_29,  /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "",
};

const xqc_cid_t *
xqc_hq_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    /* HQ is also known as HTTP/0.9, here it is used as interop protocol */
    return xqc_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag, 
                       conn_ssl_config, peer_addr, peer_addrlen,
                       xqc_hq_alpn[conn_settings->proto_version], user_data);
}

