
#include "../include/xquic.h"
#include "../common/xqc_common.h"
#include "../common/xqc_malloc.h"
#include "../common/xqc_str_hash.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "../common/xqc_priority_q.h"
#include "xqc_engine.h"
#include "xqc_cid.h"
#include "xqc_stream.h"
#include "../common/xqc_hash.h"
#include "xqc_frame_parser.h"
#include "../common/xqc_timer.h"

void xqc_conn_init_trans_param(xqc_connection_t *conn)
{
    xqc_trans_param_t *param = &conn->trans_param;
    param->max_ack_delay = 25;
    param->ack_delay_exponent = 3;
    //TODO: 临时值
    param->initial_max_data = 1*1024*1024;
    param->initial_max_stream_data_bidi_local = 100*1024;
    param->initial_max_stream_data_bidi_remote = 100*1024;
    param->initial_max_stream_data_uni = 100*1024;
    param->initial_max_streams_bidi = 3;
    param->initial_max_streams_uni = 3;
}

void xqc_conn_init_flow_ctl(xqc_connection_t *conn)
{
    xqc_trans_param_t *param = &conn->trans_param;
    xqc_conn_flow_ctl_t *flow_ctl = &conn->conn_flow_ctl;
    flow_ctl->fc_max_data = param->initial_max_data;
    flow_ctl->fc_max_streams_bidi = param->initial_max_streams_bidi;
    flow_ctl->fc_max_streams_uni = param->initial_max_streams_uni;
    flow_ctl->fc_data_sent = 0;
    flow_ctl->fc_date_recved = 0;
}

int
xqc_conns_pq_push (xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_ms)
{
    xqc_conns_pq_elem_t *elem = (xqc_conns_pq_elem_t*)xqc_pq_push(pq, time_ms);
    if (!elem) {
        return -1;
    }
    elem->conn = conn;
    return 0;
}

void
xqc_conns_pq_pop (xqc_pq_t *pq)
{
    xqc_pq_pop(pq);
}

xqc_conns_pq_elem_t *
xqc_conns_pq_top (xqc_pq_t *pq)
{
    return  (xqc_conns_pq_elem_t*)xqc_pq_top(pq);
}


static inline int
xqc_insert_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn)
{
    xqc_cid_t *dcid = &conn->dcid;

    uint64_t hash = xqc_hash_string(dcid->cid_buf, dcid->cid_len);

    xqc_str_hash_element_t c = {
            .str    = {
                        .data = dcid->cid_buf,
                        .len = dcid->cid_len
                    },
            .hash   = hash,
            .value  = conn
    };
    if (xqc_str_hash_add(conns_hash, c)) {
        return -1;
    }
    return 0;
}

static inline int
xqc_remove_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn)
{
    xqc_cid_t *dcid = &conn->dcid;
    uint64_t hash = xqc_hash_string(dcid->cid_buf, dcid->cid_len);
    xqc_str_t str = {
        .data   = dcid->cid_buf,
        .len    = dcid->cid_len,
    };
    if (xqc_str_hash_delete(conns_hash, hash, str)) {
        return -1;
    }
    return 0;
}

xqc_connection_t *
xqc_create_connection(xqc_engine_t *engine,
                                xqc_cid_t *dcid, xqc_cid_t *scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data,
                                xqc_conn_type_t type)
{
    xqc_connection_t *xc = NULL;
    xqc_memory_pool_t *pool = xqc_create_pool(engine->config->conn_pool_size);

    if (pool == NULL) {
        return NULL;
    }

    xc = xqc_pcalloc(pool, sizeof(xqc_connection_t));
    if (xc == NULL) {
        goto fail;
    }

    xqc_conn_init_trans_param(xc);
    xqc_conn_init_flow_ctl(xc);


    xc->conn_pool = pool;
    xqc_cid_copy(&(xc->dcid), dcid);
    xqc_cid_copy(&(xc->scid), scid);
    xc->engine = engine;
    xc->log = engine->log;
    xc->conn_callbacks = *callbacks;
    xc->conn_settings = *settings;
    xc->user_data = user_data;
    xc->version = XQC_QUIC_VERSION;
    xc->discard_vn_flag = 0;
    xc->conn_type = type;
    xc->conn_flag = XQC_CONN_FLAG_NONE;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xc->zero_rtt_count = 0;

    xc->conn_send_ctl = xqc_send_ctl_create(xc);
    if (xc->conn_send_ctl == NULL) {
        goto fail;
    }

    xqc_init_list_head(&xc->conn_write_streams);
    xqc_init_list_head(&xc->conn_read_streams);
    xqc_init_list_head(&xc->packet_in_tailq);

    /* create streams_hash */
    xc->streams_hash = xqc_pcalloc(xc->conn_pool, sizeof(xqc_id_hash_table_t));
    if (xc->streams_hash == NULL) {
        goto fail;
    }
    if (xqc_id_hash_init(xc->streams_hash,
                         xqc_default_allocator,
                         engine->config->streams_hash_bucket_size) == XQC_ERROR) {
        goto fail;
    }

    /* Insert into engine's conns_hash */
    if (xqc_insert_conns_hash(engine->conns_hash, xc)) {
        goto fail;
    }

    if (xqc_conns_pq_push(engine->conns_pq, xc, 0)) {
        goto fail;
    }

    for (xqc_pkt_num_space_t i = 0; i < XQC_PNS_N; i++) {
        memset(&xc->recv_record[i], 0, sizeof(xqc_recv_record_t));
        xqc_init_list_head(&xc->recv_record[i].list_head);
    }

    xc->conn_flag |= XQC_CONN_FLAG_TICKING;

    /* Do callback */
    if (xc->conn_callbacks.conn_create_notify(xc, user_data)) {
        goto fail;
    }



    return xc;

fail:
    if (pool != NULL) {
        xqc_destroy_pool(pool);
    }
    return NULL;
}


void
xqc_destroy_connection(xqc_connection_t *xc)
{
    if (!xc) {
        return;
    }
    /* free streams hash */
    if (xc->streams_hash) {
        xqc_id_hash_release(xc->streams_hash);
        xc->streams_hash = NULL;
    }

    /* free pool */
    if (xc->conn_pool) {
        xqc_destroy_pool(xc->conn_pool);
        xc->conn_pool = NULL;
    }

    /* Remove from engine's conns_hash */
    if (xc->engine->conns_hash) {
        xqc_remove_conns_hash(xc->engine->conns_hash, xc);
        xc->engine->conns_hash = NULL;
    }
}


xqc_connection_t * 
xqc_client_create_connection(xqc_engine_t *engine, 
                                xqc_cid_t dcid, xqc_cid_t scid,
                                xqc_conn_callbacks_t *callbacks,
                                xqc_conn_settings_t *settings,
                                void *user_data)
{
    xqc_connection_t *xc = xqc_create_connection(engine, &dcid, &scid, 
                                        callbacks, settings, user_data, 
                                        XQC_CONN_TYPE_CLIENT);

    if (xc == NULL) {
        return NULL;
    }
                    
    xc->cur_stream_id_bidi_local = 0;
    xc->cur_stream_id_uni_local = 2;

    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, user_data);
    if (!xc->crypto_stream[XQC_ENC_LEV_INIT]) {
        goto fail;
    }
    return xc;

fail:
    xqc_destroy_connection(xc);
    return NULL;
}

void
xqc_conn_send_packets (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (xqc_send_ctl_can_send(conn)) { //TODO: 保证packet number大的，发送时间最新
            if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT && conn->engine->eng_type == XQC_ENGINE_CLIENT) {
                xqc_gen_padding_frame(packet_out);
            }

            xqc_conn_send_one_packet(conn, packet_out);

            /* move send list to unacked list */
            xqc_send_ctl_remove_send(&packet_out->po_list);
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);

        }
    }
    //TODO: del packet_out
}

void
xqc_conn_send_one_packet (xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    conn->engine->eng_callback.write_socket(conn->user_data, packet_out->po_buf, packet_out->po_used_size);
    xqc_send_ctl_on_packet_sent(conn->conn_send_ctl, packet_out);
}

void
xqc_conn_retransmit_lost_packets(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (xqc_send_ctl_can_send(conn)) {
            xqc_conn_send_one_packet(conn, packet_out);

            xqc_send_ctl_remove_lost(&packet_out->po_list);
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
        }
    }
}

void
xqc_conn_retransmit_unacked_crypto(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_pkt_num_space_t pns;

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
                //TODO: change packet number

                xqc_conn_send_one_packet(conn, packet_out);
            }
        }
    }
}

/**
 * see https://tools.ietf.org/html/draft-ietf-quic-recovery-19#section-6.3.2
 */
void
xqc_conn_send_probe_packets(xqc_connection_t *conn)
{
    unsigned cnt = 0, probe_num = 2;
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (xqc_send_ctl_can_send(conn)) {
            xqc_conn_send_one_packet(conn, packet_out);

            /* move send list to unacked list */
            xqc_send_ctl_remove_send(&packet_out->po_list);
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
            if (++cnt >= probe_num) {
                return;
            }
        }
    }

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
                //TODO: change packet number

                xqc_conn_send_one_packet(conn, packet_out);
                if (++cnt >= probe_num) {
                    return;
                }
            }
        }
    }
}

xqc_int_t
xqc_conn_check_handshake_completed(xqc_connection_t *conn)
{
    return ((conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) != 0);
}

