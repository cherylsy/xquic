#include "xqc_h3_ctx.h"
#include "xqc_h3_conn.h"
#include "xqc_h3_stream.h"

// 应用层注册回调，放到engine
typedef struct xqc_h3_engine_s {
    xqc_h3_callbacks_t  h3_cbs;
} xqc_h3_engine_t;


xqc_h3_engine_t *h3_engine = NULL;

xqc_int_t
xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs)
{
    if (NULL == h3_engine) {
        h3_engine = xqc_malloc(sizeof(xqc_h3_engine_t));
        if (NULL == h3_engine) {
            return -XQC_EMALLOC;
        }
    }

    /* save h3 callbacks */
    h3_engine->h3_cbs = *h3_cbs;

    /* init quic level callbacks */
    xqc_quic_callbacks_t quic_cbs = {
        .conn_cbs       = h3_conn_callbacks,
        .stream_cbs     = h3_stream_callbacks
    };

    /* register ALPN and quic level callbacks */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_H3_29, XQC_ALPN_H3_29_LEN, &quic_cbs) != XQC_OK
        || xqc_engine_register_alpn(engine, XQC_ALPN_H3, XQC_ALPN_H3_LEN, &quic_cbs) != XQC_OK)
    {
        return -XQC_EFATAL;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_ctx_destroy(xqc_engine_t *engine)
{
    if (xqc_engine_unregister_alpn(engine, XQC_ALPN_H3_29, XQC_ALPN_H3_29_LEN) != XQC_OK
        || xqc_engine_unregister_alpn(engine, XQC_ALPN_H3, XQC_ALPN_H3_LEN) != XQC_OK)
    {
        return -XQC_EFATAL;
    }

    xqc_free(h3_engine);
    h3_engine = NULL;

    return XQC_OK;
}


xqc_int_t
xqc_h3_ctx_get_app_callbacks(xqc_h3_callbacks_t *h3_cbs)
{
    if (NULL == h3_engine) {
        return -XQC_EFATAL;
    }

    *h3_cbs = h3_engine->h3_cbs;
    return XQC_OK;
}
