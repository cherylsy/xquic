
#include "xqc_multipath.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_engine.h"
#include "xqc_cid.h"
#include "xqc_stream.h"
#include "xqc_utils.h"
#include "xqc_wakeup_pq.h"
#include "xqc_packet_out.h"

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_timer.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_id_hash.h"

#include "xquic/xqc_errno.h"


xqc_path_ctx_t *
xqc_path_create(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = NULL;

    path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    if (path == NULL){
        return NULL;
    }
    xqc_memzero(path, sizeof(xqc_path_ctx_t));

    path->parent_conn = conn;

    for (xqc_pkt_num_space_t i = 0; i < XQC_PNS_N; i++) {
        xqc_memzero(&path->path_recv_record[i], sizeof(xqc_recv_record_t));
        xqc_init_list_head(&path->path_recv_record[i].list_head);
    }

    path->path_state = XQC_MP_STATE_CREATED;
    path->path_status = XQC_MP_STATE_AVAILABLE;
    path->path_status_seq_number = 0;
    path->path_send_ctl = xqc_send_ctl_create(conn);

    if (path->path_send_ctl == NULL) {
        goto err;
    }

    /* TODO: should use path_ctx */
    path->path_send_ctl->ctl_conn = conn;

    /* cid & path_id init */
    if (xqc_conn_get_new_scid(conn, &(path->path_scid)) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|MP|conn don't have available scid|");
        goto err;
    }
    if (xqc_conn_get_new_dcid(conn, &(path->path_dcid)) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|MP|conn don't have available dcid|");
        goto err;
    }

    path->path_id = path->path_dcid.cid_seq_num;

    /* TODO: 4-tuple init */
    if (conn->peer_addrlen > 0) {
        xqc_memcpy(path->peer_addr, conn->peer_addr, conn->peer_addrlen);
        path->peer_addrlen = conn->peer_addrlen;
    }

    if (conn->local_addrlen > 0) {
        xqc_memcpy(path->local_addr, conn->local_addr, conn->local_addrlen);
        path->local_addrlen = conn->local_addrlen;
    }

    xqc_log(conn->engine->log, XQC_LOG_DEBUG, "|MP|init a new path (%ui): dcid=%s, scid=%s, state: %d|",
            path->path_id, xqc_dcid_str(&(path->path_dcid)), xqc_scid_str(&(path->path_scid)), 
            path->path_state);

    return path;

err:
    if (path->path_send_ctl != NULL) {
        xqc_send_ctl_destroy(path->path_send_ctl);
        path->path_send_ctl = NULL;
    }

    for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns < XQC_PNS_N; pns++) {
        xqc_recv_record_destroy(&path->path_recv_record[pns]);
    }

    xqc_free((void *)path);
    return NULL;
}

void 
xqc_path_destroy(xqc_path_ctx_t *path)
{
    if (path->path_send_ctl != NULL) {
        xqc_send_ctl_destroy(path->path_send_ctl);
        path->path_send_ctl = NULL;
    }

    for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns < XQC_PNS_N; pns++) {
        xqc_recv_record_destroy(&path->path_recv_record[pns]);
    }
 
    xqc_free((void *)path);
}

void
xqc_path_update_status(xqc_path_ctx_t *path, 
    uint64_t path_status_seq, uint64_t path_status, uint64_t path_prio)
{
    if (path_status_seq > path->path_status_seq_number) {
        path->path_status = path_status;
        path->path_prio = path_prio;
    }
}



/**
 * Check whether the connection supports multi-path or not.
 * @param conn  connection context
 * @return enable_multipath 0:not support, 1:support
 */
uint64_t
xqc_conn_enable_multipath(xqc_connection_t *conn)
{
    return (conn->remote_settings.enable_multipath && conn->local_settings.enable_multipath);
}


xqc_int_t
xqc_conn_create_path(xqc_engine_t *engine, 
    xqc_cid_t *scid, uint64_t *new_path_id)
{
    xqc_connection_t *conn = NULL;
    xqc_path_ctx_t *path = NULL;
    xqc_int_t ret = XQC_OK;

    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    /* check mp-support */
    if (!xqc_conn_enable_multipath(conn)) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|Multipath is not supported in remote host, use the first path as default!|");
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* must have at least one available unused scid & dcid */
    if (xqc_conn_check_available_cids(conn) != XQC_OK) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|don't have available cid for new path|");
        return -XQC_EMP_NO_AVAIL_PATH_ID;
    }

    path = xqc_path_create(conn);
    if (path == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_path_create error|");
        return -XQC_EMP_CREATE_PATH;
    }

    /* insert path to conn_paths_list */
    xqc_list_add_tail(&path->path_list, &conn->conn_paths_list);

    /* write path status frame & send immediately */
    ret = xqc_write_path_status_to_packet(conn, path);
    if (ret < 0) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_write_path_status_to_packet error|");
        return ret;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    *new_path_id = path->path_id;

    return XQC_OK;
}


/* destroy all the paths of the connection */
void
xqc_conn_destroy_path(xqc_connection_t *conn)
{
    xqc_list_head_t *pos = NULL, *next = NULL;
    xqc_path_ctx_t *path = NULL;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (conn->engine->conns_hash) {
            xqc_remove_conns_hash(conn->engine->conns_hash, conn, &path->path_scid);
        }

        xqc_list_del_init(pos);
        xqc_path_destroy(path);
    }
}


xqc_path_ctx_t *
xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_scid.cid_seq_num == path_id) {
            return path;
        }
    }

    return NULL;
}


