
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

#include "src/http3/xqc_h3_conn.h" /* TODO:delete me */


xqc_path_ctx_t *
xqc_path_create(xqc_connection_t *conn,
    xqc_cid_t *scid, xqc_cid_t *dcid)
{
    xqc_path_ctx_t *path = NULL;

    path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    if (path == NULL) {
        return NULL;
    }
    xqc_memzero(path, sizeof(xqc_path_ctx_t));

    path->parent_conn = conn;

    for (xqc_pkt_num_space_t i = 0; i < XQC_PNS_N; i++) {
        xqc_memzero(&path->path_recv_record[i], sizeof(xqc_recv_record_t));
        xqc_init_list_head(&path->path_recv_record[i].list_head);
    }

    path->path_state = XQC_MP_STATE_INIT;
    path->path_status = XQC_MP_STATE_AVAILABLE;
    path->path_status_seq_number = 0;
    path->path_send_ctl = xqc_send_ctl_create(conn);

    if (path->path_send_ctl == NULL) {
        goto err;
    }

    /* TODO: should use path_ctx */
    path->path_send_ctl->ctl_conn = conn;

    /* cid & path_id init */
    if (scid == NULL || dcid == NULL) {
        if (xqc_get_unused_cid(&(conn->scid_set.cid_set), &(path->path_scid)) != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|MP|conn don't have available scid|");
            goto err;
        }
        if (xqc_get_unused_cid(&(conn->dcid_set.cid_set), &(path->path_dcid)) != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|MP|conn don't have available dcid|");
            goto err;
        }

    } else {
        /* already have scid & dcid */

        xqc_cid_copy(&(path->path_scid), scid);
        xqc_cid_copy(&(path->path_dcid), dcid);
    }

    path->path_id = path->path_scid.cid_seq_num;

    /* insert path to conn_paths_list */
    xqc_list_add_tail(&path->path_list, &conn->conn_paths_list);

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

xqc_int_t
xqc_path_init(xqc_path_ctx_t *path,
    xqc_connection_t *conn)
{
    xqc_int_t ret = XQC_ERROR;

    /* write path status frame & send immediately */
    ret = xqc_write_path_status_to_packet(conn, path);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_status_to_packet error|");
        return ret;
    }

    path->path_state = XQC_MP_STATE_CREATED;

    /* create path notify */
    if (path->path_id != XQC_MP_INITIAL_PATH_ID
        && conn->transport_cbs.path_created_notify)
    {
        conn->transport_cbs.path_created_notify(&conn->scid_set.user_scid, path->path_id, 
                                                xqc_conn_get_user_data(conn));
    }

    /* TODO: 4-tuple init */
    if (conn->peer_addrlen > 0) {
        xqc_memcpy(path->peer_addr, conn->peer_addr, conn->peer_addrlen);
        path->peer_addrlen = conn->peer_addrlen;
    }

    if (conn->local_addrlen > 0) {
        xqc_memcpy(path->local_addr, conn->local_addr, conn->local_addrlen);
        path->local_addrlen = conn->local_addrlen;
    }

    return XQC_OK;
}



/* Traverse unack packets queue and move them to loss packets queue for retransmission */
void
xqc_path_move_unack_packets_from_conn(xqc_path_ctx_t *path, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po = NULL;
    xqc_send_ctl_t *parent_ctl = conn->conn_send_ctl;
    xqc_send_ctl_t *path_send_ctl = path->path_send_ctl;
    uint64_t closing_path_id = path->path_id;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[XQC_PNS_APP_DATA]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (xqc_send_ctl_indirectly_ack_po(parent_ctl, po)) {
            continue;
        }

        if (po->po_path_id == closing_path_id) {
            if (po->po_flag & XQC_POF_IN_FLIGHT) {
                xqc_send_ctl_decrease_inflight(path_send_ctl, po);
                /*In the worst case, we have two redundant pkts on the same path.*/
                xqc_send_ctl_copy_to_lost(po, conn->conn_send_ctl);
            }
        }
    }
}

void
xqc_path_close(xqc_path_ctx_t *path,
    xqc_connection_t *conn, xqc_path_close_mode_t close_mode)
{
    if (path == NULL) {
        return;
    }

    xqc_log(conn->engine->log, XQC_LOG_DEBUG, "|path_close: %lu|", path->path_id);

    xqc_path_move_unack_packets_from_conn(path, conn);

    path->path_state = XQC_MP_STATE_CLOSED;
    path->path_status = XQC_MP_STATE_ABANDON;

    if (close_mode == XQC_MP_PATH_CLOSE_PROACTIVE) {
        xqc_write_path_status_to_packet(conn, path);
    }
}


void
xqc_path_update_status(xqc_path_ctx_t *path, 
    uint64_t path_status_seq, uint64_t path_status, uint64_t path_prio)
{
    if (path == NULL) {
        return;
    }

    if (path_status_seq > path->path_status_seq_number) {
        path->path_status = path_status;
        path->path_prio = path_prio;
    }

    xqc_log(path->parent_conn->log, XQC_LOG_DEBUG, 
                            "|path %ui update status %ui, seq %ui|", 
                            path->path_id, path->path_status, path->path_status_seq_number);
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
    const xqc_cid_t *scid, uint64_t *new_path_id)
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
        xqc_log(conn->log, XQC_LOG_WARN,
                "|Multipath is not supported in remote host, use the first path as default!|");
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* must have at least one available unused scid & dcid */
    if (xqc_conn_check_unused_cids(conn) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|don't have available cid for new path|");
        return -XQC_EMP_NO_AVAIL_PATH_ID;
    }

    path = xqc_path_create(conn, NULL, NULL);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_create error|");
        return -XQC_EMP_CREATE_PATH;
    }

    ret = xqc_path_init(path, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_init err=%d|", ret);
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


