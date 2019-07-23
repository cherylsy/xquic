
#include <common/xqc_errno.h>
#include "../include/xquic.h"
#include "../common/xqc_common.h"
#include "../common/xqc_malloc.h"
#include "../common/xqc_str_hash.h"
#include "../common/xqc_timer.h"
#include "../common/xqc_hash.h"
#include "../common/xqc_priority_q.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_engine.h"
#include "xqc_cid.h"
#include "xqc_stream.h"
#include "xqc_frame_parser.h"
#include "xqc_packet_parser.h"

static char g_conn_flag_buf[128];

static const char * const conn_flag_2_str[XQC_CONN_FLAG_SHIFT_NUM] = {
        [XQC_CONN_FLAG_WAKEUP_SHIFT]                = "WAKEUP",
        [XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT]   = "HSK_DONE",
        [XQC_CONN_FLAG_TICKING_SHIFT]               = "TICKING",
        [XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT]       = "ACK_INIT",
        [XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT]        = "ACK_HSK",
        [XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT]      = "ACK_01RTT",
        [XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT]           = "HAS_GAP",
        [XQC_CONN_FLAG_TIME_OUT_SHIFT]              = "TIME_OUT",
        [XQC_CONN_FLAG_ERROR_SHIFT]                 = "ERROR",
        [XQC_CONN_FLAG_DATA_BLOCKED_SHIFT]          = "DATA_BLOCKED",
        [XQC_CONN_FLAG_DCID_OK_SHIFT]               = "DCID_OK",
        [XQC_CONN_FLAG_TOKEN_OK_SHIFT]              = "TOKEN_OK"
};

const char*
xqc_conn_flag_2_str (xqc_conn_flag_t conn_flag)
{
    g_conn_flag_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_CONN_FLAG_SHIFT_NUM; i++) {
        if (conn_flag & 1 << i) {
            wsize = snprintf(g_conn_flag_buf + pos, sizeof(g_conn_flag_buf) - pos, "%s ", conn_flag_2_str[i]);
            pos += wsize;
        }
    }
    return g_conn_flag_buf;
}

static const char * const conn_state_2_str[XQC_CONN_STATE_N] = {
        [XQC_CONN_STATE_SERVER_INIT]            = "S_INIT",
        [XQC_CONN_STATE_SERVER_INITIAL_RECVD]   = "S_INITIAL_RECVD",
        [XQC_CONN_STATE_SERVER_INITIAL_SENT]    = "S_INITIAL_SENT",
        [XQC_CONN_STATE_SERVER_HANDSHAKE_SENT]  = "S_HANDSHAKE_SENT",
        [XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD] = "S_HANDSHAKE_RECVD",
        [XQC_CONN_STATE_CLIENT_INIT]            = "C_INIT",
        [XQC_CONN_STATE_CLIENT_INITIAL_RECVD]   = "C_INITIAL_RECVD",
        [XQC_CONN_STATE_CLIENT_INITIAL_SENT]    = "C_INITIAL_SENT",
        [XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT]  = "C_HANDSHAKE_SENT",
        [XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD] = "C_HANDSHAKE_RECVD",
        [XQC_CONN_STATE_ESTABED]                = "ESTABED",
        [XQC_CONN_STATE_CLOSING]                = "CLOSING",
        [XQC_CONN_STATE_DRAINING]               = "DRAINING",
        [XQC_CONN_STATE_CLOSED]                 = "CLOSED",

};

const char *
xqc_conn_state_2_str(xqc_conn_state_t state)
{
    return conn_state_2_str[state];
}

void xqc_conn_init_trans_param(xqc_connection_t *conn)
{
    xqc_trans_param_t *param = &conn->trans_param;
    param->max_ack_delay = 25;
    param->ack_delay_exponent = 3;
    //TODO: 临时值
    param->idle_timeout = 5000;
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|");
        return -XQC_ENULLPTR;
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

int
xqc_insert_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid)
{
    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);

    xqc_str_hash_element_t c = {
            .str    = {
                    .data = cid->cid_buf,
                    .len = cid->cid_len
            },
            .hash   = hash,
            .value  = conn
    };
    if (xqc_str_hash_add(conns_hash, c)) {
        return -XQC_EMALLOC;
    }
    return 0;
}

int
xqc_remove_conns_hash (xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid)
{
    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str = {
            .data   = cid->cid_buf,
            .len    = cid->cid_len,
    };
    if (xqc_str_hash_delete(conns_hash, hash, str)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_str_hash_delete error");
        return -XQC_ECONN_NFOUND;
    }
    return 0;
}

int
xqc_insert_conns_addr_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
    uint64_t hash = xqc_hash_string((unsigned char*)addr, addrlen);
    xqc_str_hash_element_t c = {
            .str    = {
                    .data = (unsigned char*)addr,
                    .len = addrlen
                    },
            .hash   = hash,
            .value  = conn
    };
    if (xqc_str_hash_add(conns_hash, c)) {
        return -XQC_EMALLOC;
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
    xc->conn_flag = 0;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xc->zero_rtt_count = 0;

    xc->conn_send_ctl = xqc_send_ctl_create(xc);
    if (xc->conn_send_ctl == NULL) {
        goto fail;
    }

    xqc_init_list_head(&xc->conn_write_streams);
    xqc_init_list_head(&xc->conn_read_streams);
    xqc_init_list_head(&xc->conn_all_streams);
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
    if (xqc_insert_conns_hash(engine->conns_hash, xc, &xc->scid)) {
        goto fail;
    }

    /* 客户端创建连接时，服务端的cid还未生成 */
    if (type == XQC_CONN_TYPE_SERVER) {
        if (xqc_insert_conns_hash(engine->conns_hash_dcid, xc, &xc->dcid)) {
            goto fail;
        }
        xc->conn_flag |= XQC_CONN_FLAG_DCID_OK;
    }

    if (xqc_conns_pq_push(engine->conns_pq, xc, 0)) {
        goto fail;
    }
    xc->conn_flag |= XQC_CONN_FLAG_TICKING;

    for (xqc_pkt_num_space_t i = 0; i < XQC_PNS_N; i++) {
        memset(&xc->recv_record[i], 0, sizeof(xqc_recv_record_t));
        xqc_init_list_head(&xc->recv_record[i].list_head);
    }

    /* Do callback */
    if (xc->conn_type == XQC_CONN_TYPE_SERVER && xc->conn_callbacks.conn_create_notify) {
        if (xc->conn_callbacks.conn_create_notify(&xc->scid, user_data)) {
            goto fail;
        }
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

    if (xc->conn_callbacks.conn_close_notify) {
        xc->conn_callbacks.conn_close_notify(&xc->scid, xc->user_data);
    }

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;

    xqc_log(xc->log, XQC_LOG_DEBUG, "xqc_destroy_connection %p", xc);
    xqc_log(xc->log, XQC_LOG_DEBUG, "srtt: %ui, retrans rate: %.2f, send_count: %ui, retrans_count: %ui",
            xqc_send_ctl_get_srtt(xc->conn_send_ctl), xqc_send_ctl_get_retrans_rate(xc->conn_send_ctl),
            xc->conn_send_ctl->ctl_send_count, xc->conn_send_ctl->ctl_retrans_count);

    xqc_send_ctl_destroy(xc->conn_send_ctl);

    /* free streams hash */
    if (xc->streams_hash) {
        xqc_id_hash_release(xc->streams_hash);
        xc->streams_hash = NULL;
    }

    /* destroy streams */
    xqc_list_for_each_safe(pos, next, &xc->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_list_del_init(pos);
        xqc_destroy_stream(stream);
    }

    /* Remove from engine's conns_hash */
    if (xc->engine->conns_hash) {
        xqc_remove_conns_hash(xc->engine->conns_hash, xc, &xc->scid);
    }
    if (xc->engine->conns_hash_dcid && (xc->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
        xqc_remove_conns_hash(xc->engine->conns_hash_dcid, xc, &xc->dcid);
    }

    /* free pool */
    if (xc->conn_pool) {
        xqc_destroy_pool(xc->conn_pool);
        xc->conn_pool = NULL;
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

    xqc_cid_copy(&(xc->ocid), &(xc->dcid));

    xc->cur_stream_id_bidi_local = 0;
    xc->cur_stream_id_uni_local = 2;

    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, XQC_ENC_LEV_INIT, user_data);
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
    xqc_send_ctl_t *ctl = conn->conn_send_ctl;
    ssize_t ret;

    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_SHORT_HEADER &&
            !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)) {
            xqc_log(conn->log, XQC_LOG_WARN, "HSK NOT FINISHED");
            return;
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            if (!xqc_send_ctl_can_send(conn)) {
                return;
            } else if (conn->conn_settings.pacing_on) {
                xqc_pacing_schedule(&ctl->ctl_pacing, ctl);
                if (!xqc_pacing_can_send(&ctl->ctl_pacing, ctl)) {
                    xqc_send_ctl_timer_set(ctl, XQC_TIMER_PACING, ctl->ctl_pacing.next_send_time);
                    return;
                }
            }
        }

        if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT && conn->engine->eng_type == XQC_ENGINE_CLIENT
                && packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
            xqc_gen_padding_frame(packet_out);
        }

        ret = xqc_conn_send_one_packet(conn, packet_out);
        if (ret < 0) {
            return;
        }

        /* move send list to unacked list */
        xqc_send_ctl_remove_send(&packet_out->po_list);
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
        }
        else {
            xqc_send_ctl_insert_free(pos, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
        }

    }
}

ssize_t
xqc_conn_send_one_packet (xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    ssize_t sent;

    /* generate packet number */
    packet_out->po_pkt.pkt_num = conn->conn_send_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;
    xqc_write_packet_number(packet_out->ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);

    if (!(packet_out->po_flag & XQC_POF_ENCRYPTED)) {
        //do encrypt
        packet_out->po_flag |= XQC_POF_ENCRYPTED;
    }

    sent = conn->engine->eng_callback.write_socket(conn->user_data, packet_out->po_buf, packet_out->po_used_size);
    xqc_log(conn->log, XQC_LOG_INFO, "<== xqc_conn_send_one_packet conn=%p, size=%ui, sent=%ui, pkt_type=%s, pkt_num=%ui, frame=%s",
            conn, packet_out->po_used_size, sent,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type), packet_out->po_pkt.pkt_num,
            xqc_frame_type_2_str(packet_out->po_frame_types));
    if (sent != packet_out->po_used_size) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_send_one_packet|write_socket error|"
                                          "conn=%p, size=%ui, sent=%ui, pkt_type=%s, pkt_num=%ui, frame=%s",
                conn, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type), packet_out->po_pkt.pkt_num,
                xqc_frame_type_2_str(packet_out->po_frame_types));
        return -XQC_ESOCKET;
    }
    xqc_send_ctl_on_packet_sent(conn->conn_send_ctl, packet_out);

    return sent;
}

void
xqc_conn_retransmit_lost_packets(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    ssize_t ret;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_conn_retransmit_lost_packets|");
        packet_out->po_flag |= XQC_POF_RETRANS;

        ret = xqc_conn_send_one_packet(conn, packet_out);
        if (ret < 0) {
            return;
        }
        xqc_send_ctl_remove_lost(&packet_out->po_list);
        xqc_send_ctl_insert_unacked(packet_out,
                                    &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                    conn->conn_send_ctl);

    }
}

void
xqc_conn_retransmit_unacked_crypto(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_pkt_num_space_t pns;
    int ret;

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            packet_out->po_flag |= XQC_POF_RETRANS;

            if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {

                ret = xqc_conn_send_one_packet(conn, packet_out);
                if (ret < 0) {
                    return;
                }
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
    int ret;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ret = xqc_conn_send_one_packet(conn, packet_out);
            if (ret < 0) {
                return;
            }

            /* move send list to unacked list */
            xqc_send_ctl_remove_send(&packet_out->po_list);
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
        }

        if (++cnt >= probe_num) {
            return;
        }
    }

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {

                ret = xqc_conn_send_one_packet(conn, packet_out);
                if (ret < 0) {
                    return;
                }
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

xqc_msec_t
xqc_conn_next_wakeup_time(xqc_connection_t *conn)
{
    xqc_msec_t min_time = XQC_MAX_UINT64_VALUE;
    xqc_msec_t wakeup_time;
    xqc_send_ctl_timer_t *timer;
    xqc_send_ctl_t *ctl = conn->conn_send_ctl;

    for (xqc_send_ctl_timer_type type = 0; type < XQC_TIMER_N; ++type) {
        timer = &ctl->ctl_timer[type];
        if (timer->ctl_timer_is_set) {
            min_time = xqc_min(min_time, timer->ctl_expire_time);
        }
    }

    wakeup_time = min_time == XQC_MAX_UINT64_VALUE ? 0 : min_time;

    xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_conn_next_wakeup_time: %ui", wakeup_time);

    return wakeup_time;
}

int
xqc_conn_close(xqc_engine_t *engine, xqc_cid_t *cid)
{
    int ret;
    xqc_connection_t *conn;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_conn_close|can not find connection");
        return -XQC_ECONN_NFOUND;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_conn_close %p", conn);

    ret = xqc_conn_immediate_close(conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_conn_close xqc_conn_immediate_close error");
        return ret;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_engine_main_logic(conn->engine);

    return XQC_OK;
}

int
xqc_conn_immediate_close(xqc_connection_t *conn)
{
    int ret;
    xqc_send_ctl_t *ctl;
    xqc_msec_t now;

    xqc_send_ctl_drop_packets(conn->conn_send_ctl);

    ret = xqc_write_conn_close_to_packet(conn, conn->conn_err);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_conn_close xqc_write_conn_close_to_packet error");
        return ret;
    }


    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        conn->conn_state = XQC_CONN_STATE_CLOSING;

        ctl = conn->conn_send_ctl;
        now = xqc_now();
        xqc_msec_t pto = xqc_send_ctl_calc_pto(ctl);
        if (!xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_DRAINING)) {
            xqc_send_ctl_timer_set(ctl, XQC_TIMER_DRAINING, 3 * pto + now);
        }

        for (int i = 0; i <= XQC_TIMER_LOSS_DETECTION; i++) {
            xqc_send_ctl_timer_unset(ctl, i);
        }
    }
    return XQC_OK;
}

int
xqc_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid, void *user_data)
{
    unsigned char buf[XQC_PACKET_OUT_SIZE];
    int size;

    size = (int)xqc_gen_reset_packet(dcid, buf);
    if (size < 0) {
        return size;
    }

    size = (int)engine->eng_callback.write_socket(user_data, buf, (size_t)size);
    if (size < 0) {
        return size;
    }

    xqc_log(engine->log, XQC_LOG_WARN, "xqc_send_reset ok, size=%d", size);
    return XQC_OK;
}

int
xqc_send_retry(xqc_connection_t *conn, unsigned char *token, unsigned token_len)
{
    xqc_engine_t *engine = conn->engine;
    unsigned char buf[XQC_PACKET_OUT_SIZE];
    int size;

    size = (int)xqc_gen_retry_packet(buf,
                                     conn->dcid.cid_buf, conn->dcid.cid_len,
                                     conn->scid.cid_buf, conn->scid.cid_len,
                                     conn->ocid.cid_buf, conn->ocid.cid_len,
                                     token, token_len, XQC_QUIC_VERSION);
    if (size < 0) {
        return size;
    }

    size = (int)engine->eng_callback.write_socket(conn->user_data, buf, (size_t)size);
    if (size < 0) {
        return size;
    }

    xqc_log(engine->log, XQC_LOG_WARN, "xqc_send_retry ok, size=%d", size);
    return XQC_OK;
}

int
xqc_conn_write_handler(xqc_engine_t *engine, xqc_cid_t *cid)
{
    xqc_connection_t *conn;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_conn_write_handler|can not find connection");
        return -XQC_ECONN_NFOUND;
    }
    xqc_conn_send_packets(conn);
    xqc_engine_main_logic(conn->engine);

    return XQC_OK;
}

int
xqc_conn_check_token(xqc_connection_t *conn, const unsigned char *token, unsigned token_len)
{
    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|exceed XQC_MAX_TOKEN_LEN");
        return 0;
    }

    struct sockaddr *sa = (struct sockaddr *)conn->peer_addr;
    const unsigned char *pos = token;
    if (*pos++ & 0x80) {
        struct in6_addr *in6 = (struct in6_addr *)pos;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)sa;
        if (token_len != 21) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|token_len error|token_len:%ui|", token_len);
            return 0;
        }
        if (memcmp(&sa6->sin6_addr, in6, sizeof(struct in6_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|ipv6 not match");
            return 0;
        }
        pos += sizeof(struct in6_addr);

    } else {
        struct in_addr *in4 = (struct in_addr *)pos;
        struct sockaddr_in *sa4 = (struct sockaddr_in*)sa;
        if (token_len != 9) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|token_len error|token_len:%ui|", token_len);
            return 0;
        }
        if (memcmp(&sa4->sin_addr, in4, sizeof(struct in_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|ipv4 not match");
            return 0;
        }
        pos += sizeof(struct in_addr);
    }

    uint32_t *expire = (uint32_t*)pos;
    *expire = ntohl(*expire);

    xqc_msec_t now = xqc_now() / 1000000;
    if (*expire < now) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_check_token|token_expire %ui", *expire);
        return 0;
    }

    if (*expire < now + XQC_TOKEN_UPDATE_DELTA) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_conn_check_token|new token %ui", *expire);
        xqc_write_new_token_to_packet(conn);
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_conn_check_token|pass");
    return 1;
}

/*
+-+-+-+-+-+-+-+-+
|v|0|0|0|0|0|0|0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     IP(32/128)                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Expire Time(32)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 v: 0 For IPv4, 1 For IPv6
 */
void
xqc_conn_gen_token(xqc_connection_t *conn, unsigned char *token, unsigned *token_len)
{
    struct sockaddr *sa = (struct sockaddr *)conn->peer_addr;
    if (sa->sa_family == AF_INET) {
        *token++ = 0x00;
        struct sockaddr_in *sa4 = (struct sockaddr_in*)sa;
        memcpy(token, &sa4->sin_addr, sizeof(struct in_addr));
        token += sizeof(struct in_addr);

        *token_len = 9;
    } else {
        *token++ = 0x80;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)sa;
        memcpy(token, &sa6->sin6_addr, sizeof(struct in6_addr));
        token += sizeof(struct in6_addr);

        *token_len = 21;
    }

    uint32_t expire = xqc_now() / 1000000 + XQC_TOKEN_EXPIRE_DELTA;
    expire = htonl(expire);
    memcpy(token, &expire, sizeof(expire));

}
