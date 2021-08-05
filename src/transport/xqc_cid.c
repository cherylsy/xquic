
#include <xquic/xquic.h>
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_random.h"

xqc_int_t
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *ori_cid, xqc_cid_t *cid,
    uint64_t cid_seq_num)
{
    unsigned char *buf;
    ssize_t len, written;

    cid->cid_seq_num = cid_seq_num;
    cid->cid_len = engine->config->cid_len;

    buf = cid->cid_buf;
    len = cid->cid_len;

    if (engine->eng_callback.cid_generate_cb) {
        written = engine->eng_callback.cid_generate_cb(ori_cid, buf, len, engine->user_data);
        if (written < XQC_OK) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|generate cid failed [ret=%d]|", written);
            return -XQC_EGENERATE_CID;
        }
        buf += written;
        len -= written;
    }

    if (len > 0 && (xqc_get_random(engine->rand_generator, buf, len) != XQC_OK)) {
        return -XQC_EGENERATE_CID;
    }

    return XQC_OK;
}


xqc_int_t
xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src)
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
    dst->cid_seq_num = src->cid_seq_num;
}

void
xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    xqc_memzero(cid->cid_buf, XQC_MAX_CID_LEN);
    cid->cid_seq_num = 0;
}

void
xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len)
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
xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid)
{
    xqc_connection_t *conn;
    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return NULL;
    }

    xqc_hex_dump(conn->dcid_set.dcid_str, conn->dcid_set.current_dcid.cid_buf, conn->dcid_set.current_dcid.cid_len);
    conn->dcid_set.dcid_str[conn->dcid_set.current_dcid.cid_len * 2] = '\0';

    return conn->dcid_set.dcid_str;
}

void
xqc_init_scid_set(xqc_scid_set_t *scid_set)
{
    xqc_init_list_head(&scid_set->list_head);
    scid_set->largest_scid_seq_num = 0;
    scid_set->unused_cnt = 0;
    scid_set->retired_cnt = 0;
}

void
xqc_init_dcid_set(xqc_dcid_set_t *dcid_set)
{
    xqc_init_list_head(&dcid_set->list_head);
    dcid_set->largest_retire_prior_to = 0;
    dcid_set->unused_cnt = 0;
    dcid_set->retired_cnt = 0;
}

void
xqc_destroy_scid_set(xqc_scid_set_t *scid_set)
{
    xqc_cid_inner_t *scid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        xqc_list_del(pos);
        xqc_free(scid);
    }
}

void
xqc_destroy_dcid_set(xqc_dcid_set_t *dcid_set)
{
    xqc_cid_inner_t *dcid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &dcid_set->list_head) {
        dcid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        xqc_list_del(pos);
        xqc_free(dcid);
    }
}


xqc_int_t
xqc_scid_set_insert_cid(xqc_scid_set_t *scid_set, xqc_cid_t *cid, xqc_cid_state_t state)
{
    xqc_cid_inner_t *scid = xqc_malloc(sizeof(xqc_cid_inner_t));
    if (scid == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_cid_copy(&scid->cid, cid);
    scid->state = state;
    scid->retired_ts = XQC_MAX_UINT64_VALUE;

    xqc_init_list_head(&scid->list);
    xqc_list_add_tail(&scid->list, &scid_set->list_head); 

    if (state == XQC_CID_UNUSED) {
        scid_set->unused_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_dcid_set_insert_cid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid, xqc_cid_state_t state)
{
    xqc_cid_inner_t *dcid = xqc_malloc(sizeof(xqc_cid_inner_t));
    if (dcid == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_cid_copy(&dcid->cid, cid);
    dcid->state = state;
    dcid->retired_ts = XQC_MAX_UINT64_VALUE;

    xqc_init_list_head(&dcid->list);
    xqc_list_add_tail(&dcid->list, &dcid_set->list_head);

    if (state == XQC_CID_UNUSED) {
        dcid_set->unused_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_scid_set_delete_cid(xqc_scid_set_t *scid_set, xqc_cid_t *cid)
{
    xqc_cid_inner_t *scid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &scid->cid) == XQC_OK) {
            xqc_list_del(pos);
            xqc_free(scid);
            return XQC_OK;
        }
    }

    return XQC_ERROR;
}

xqc_int_t
xqc_dcid_set_delete_cid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid)
{
    xqc_cid_inner_t *dcid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &dcid_set->list_head) {
        dcid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &dcid->cid) == XQC_OK) {
            xqc_list_del(pos);
            xqc_free(dcid);
            return XQC_OK;
        }
    }

    return XQC_ERROR;
}

xqc_cid_inner_t*
xqc_cid_in_scid_set(const xqc_cid_t *cid, const xqc_scid_set_t *scid_set)
{
    xqc_cid_inner_t *scid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &scid->cid) == XQC_OK) {
            return scid;
        }
    }

    return NULL;
}

xqc_cid_inner_t*
xqc_cid_in_dcid_set(const xqc_cid_t *cid, const xqc_dcid_set_t *dcid_set)
{
    xqc_cid_inner_t *dcid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &dcid_set->list_head) {
        dcid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &dcid->cid) == XQC_OK) {
            return dcid;
        }
    }

    return NULL;
}


xqc_int_t
xqc_scid_switch_to_next_state(xqc_scid_set_t *scid_set, xqc_cid_inner_t *scid)
{
    switch (scid->state) {

    case XQC_CID_UNUSED:
        scid->state = XQC_CID_USED;
        scid_set->unused_cnt--;
        break;
    case XQC_CID_USED:
        scid->state = XQC_CID_RETIRED;
        scid_set->retired_cnt++;
        break;
    case XQC_CID_RETIRED:
        scid->state = XQC_CID_REMOVED;
        scid_set->retired_cnt--;
        break;
    default:
        return XQC_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_dcid_switch_to_next_state(xqc_dcid_set_t *dcid_set, xqc_cid_inner_t *dcid)
{
    switch (dcid->state) {

    case XQC_CID_UNUSED:
        dcid->state = XQC_CID_USED;
        dcid_set->unused_cnt--;
        break;
    case XQC_CID_USED:
        dcid->state = XQC_CID_RETIRED;
        dcid_set->retired_cnt++;
        break;
    case XQC_CID_RETIRED:
        dcid->state = XQC_CID_REMOVED;
        dcid_set->retired_cnt--;
        break;
    default:
        return XQC_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_get_unused_dcid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid)
{
    if (dcid_set->unused_cnt == 0) {
        return -XQC_ECONN_NO_AVAIL_CID;
    }

    xqc_cid_inner_t *dcid;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &dcid_set->list_head) {
        dcid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (dcid->state == XQC_CID_UNUSED) {
            xqc_cid_copy(cid, &(dcid->cid));
            return xqc_dcid_switch_to_next_state(dcid_set, dcid);
        }
    }

    return -XQC_ECONN_NO_AVAIL_CID;
}


xqc_int_t
xqc_get_unused_scid(xqc_scid_set_t *scid_set, xqc_cid_t *cid)
{
    if (scid_set->unused_cnt == 0) {
        return -XQC_ECONN_NO_AVAIL_CID;
    }

    xqc_cid_inner_t *scid;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (scid->state == XQC_CID_UNUSED) {
            xqc_cid_copy(cid, &scid->cid);
            return xqc_scid_switch_to_next_state(scid_set, scid);
        }
    }

    return -XQC_ECONN_NO_AVAIL_CID;
}


xqc_cid_t *
xqc_get_dcid_by_seq(xqc_dcid_set_t *dcid_set, uint64_t seq_num)
{
    xqc_cid_inner_t *dcid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &dcid_set->list_head) {
        dcid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (dcid->cid.cid_seq_num == seq_num) {
            return &dcid->cid;
        }
    }

    return NULL;
}

xqc_cid_t *
xqc_get_scid_by_seq(xqc_scid_set_t *scid_set, uint64_t seq_num)
{
    xqc_cid_inner_t *scid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (scid->cid.cid_seq_num == seq_num) {
            return &scid->cid;
        }
    }

    return NULL;
}