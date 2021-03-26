
#include <xquic/xquic.h>
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_random.h"

xqc_int_t 
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *cid)
{
    unsigned char *buf;
    int len, written;

    cid->cid_len = engine->config->cid_len;

    buf = cid->cid_buf;
    len = cid->cid_len;

    if (engine->eng_callback.cid_generate_cb) {
        written = engine->eng_callback.cid_generate_cb(cid, engine->user_data);
        if (written < XQC_OK) {
            return XQC_ERROR;
        }
        buf += written;
        len -= written;
    }

    if (len > 0 && (xqc_get_random(engine->rand_generator, buf, len) != XQC_OK)) {
        return XQC_ERROR;
    }

    return XQC_OK;
}


xqc_int_t 
xqc_cid_is_equal(xqc_cid_t *dst, xqc_cid_t *src)
{
    if (dst == NULL || src == NULL) {
        return XQC_ERROR;
    }

    if (dst->cid_len != src->cid_len) {
        return XQC_ERROR;
    }

    if (xqc_memcmp(dst->cid_buf, src->cid_buf, dst->cid_len)) {
        return XQC_ERROR;
    }

    return XQC_OK;
}

void 
xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src)
{
    dst->cid_len = src->cid_len;
    xqc_memcpy(dst->cid_buf, src->cid_buf, dst->cid_len);
}

void 
xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    xqc_memzero(cid->cid_buf, XQC_MAX_CID_LEN);
}

void 
xqc_cid_set(xqc_cid_t *cid, unsigned char *data, uint8_t len)
{
    cid->cid_len = len;
    xqc_memcpy(cid->cid_buf, data, len);
}

static unsigned char g_scid_buf[XQC_MAX_CID_LEN * 2 + 1];
static unsigned char g_dcid_buf[XQC_MAX_CID_LEN * 2 + 1];

unsigned char*
xqc_dcid_str(const xqc_cid_t *dcid)
{
    xqc_hex_dump(g_dcid_buf, dcid->cid_buf, dcid->cid_len);
    g_dcid_buf[dcid->cid_len * 2] = '\0';
    return g_dcid_buf;
}

unsigned char*
xqc_scid_str(const xqc_cid_t *scid)
{
    xqc_hex_dump(g_scid_buf, scid->cid_buf, scid->cid_len);
    g_scid_buf[scid->cid_len * 2] = '\0';
    return g_scid_buf;
}

unsigned char*
xqc_dcid_str_by_scid(xqc_engine_t *engine, xqc_cid_t *scid)
{
    xqc_connection_t *conn;
    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return NULL;
    }
    return conn->dcid_str;
}