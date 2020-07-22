#include <xquic/xquic.h>
#include <errno.h>
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/common/xqc_algorithm.h"
#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_timer.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_id_hash.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/crypto/xqc_tls_header.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_wakeup_pq.h"

xqc_conn_settings_t default_conn_settings = {
        .pacing_on  =   0,
        .ping_on    =   0,
        .so_sndbuf  =   0,
};

void
xqc_server_set_conn_settings(xqc_conn_settings_t settings)
{
    default_conn_settings.cong_ctrl_callback = settings.cong_ctrl_callback;
    default_conn_settings.cc_params = settings.cc_params;
    default_conn_settings.pacing_on = settings.pacing_on;
    default_conn_settings.ping_on = settings.ping_on;
    default_conn_settings.so_sndbuf = settings.so_sndbuf;
}

static char g_conn_flag_buf[256];

static const char * const conn_flag_2_str[XQC_CONN_FLAG_SHIFT_NUM] = {
        [XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT]           = "WAIT_WAKEUP",
        [XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT]   = "HSK_DONE",
        [XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT]         = "CAN_SEND_1RTT",
        [XQC_CONN_FLAG_TICKING_SHIFT]               = "TICKING",
        [XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT]       = "ACK_INIT",
        [XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT]        = "ACK_HSK",
        [XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT]      = "ACK_01RTT",
        [XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT]           = "HAS_GAP",
        [XQC_CONN_FLAG_TIME_OUT_SHIFT]              = "TIME_OUT",
        [XQC_CONN_FLAG_ERROR_SHIFT]                 = "ERROR",
        [XQC_CONN_FLAG_DATA_BLOCKED_SHIFT]          = "DATA_BLOCKED",
        [XQC_CONN_FLAG_DCID_OK_SHIFT]               = "DCID_OK",
        [XQC_CONN_FLAG_TOKEN_OK_SHIFT]              = "TOKEN_OK",
        [XQC_CONN_FLAG_HAS_0RTT_SHIFT]              = "HAS_0RTT",
        [XQC_CONN_FLAG_0RTT_OK_SHIFT]               = "0RTT_OK",
        [XQC_CONN_FLAG_0RTT_REJ_SHIFT]              = "0RTT_REJECT",
        [XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT]      = "UPPER_CONN_EXIST",
        [XQC_CONN_FLAG_SVR_INIT_RECVD_SHIFT]        = "INIT_RECVD",
        [XQC_CONN_FLAG_NEED_RUN_SHIFT]              = "NEED_RUN",
        [XQC_CONN_FLAG_PING_SHIFT]                  = "PING",
        [XQC_CONN_FLAG_HSK_ACKED_SHIFT]             = "HSK_ACKED",
        [XQC_CONN_FLAG_CANNOT_DESTROY_SHIFT]        = "CANNOT_DESTROY",
        [XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT]  = "HSK_DONE_RECVD",
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

#ifdef XQC_PRINT_SECRET
static const char * const xqc_secret_type_2_str[SECRET_TYPE_NUM] = {
        [CLIENT_EARLY_TRAFFIC_SECRET]           = "CLIENT_EARLY_TRAFFIC_SECRET",
        [CLIENT_HANDSHAKE_TRAFFIC_SECRET]       = "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        [SERVER_HANDSHAKE_TRAFFIC_SECRET]       = "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        [CLIENT_TRAFFIC_SECRET_0]               = "CLIENT_TRAFFIC_SECRET_0",
        [SERVER_TRAFFIC_SECRET_0]               = "SERVER_TRAFFIC_SECRET_0",
};
#endif

void xqc_conn_init_trans_param(xqc_connection_t *conn)
{
    memset(&conn->local_settings, 0, sizeof(xqc_trans_settings_t));

    xqc_trans_settings_t *settings = &conn->local_settings;

    settings->max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    settings->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    //TODO: 临时值
    settings->idle_timeout = 120000; //must > XQC_PING_TIMEOUT
    settings->max_data = 1*1024*1024;
    settings->max_stream_data_bidi_local = 5*1024*1024;
    settings->max_stream_data_bidi_remote = 5*1024*1024;
    settings->max_stream_data_uni = 1024*1024;
    settings->max_streams_bidi = 1024;
    settings->max_streams_uni = 1024;
    settings->max_udp_payload_size = XQC_MAX_PKT_SIZE;
    settings->active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

    memcpy(&conn->remote_settings, &conn->local_settings, sizeof(xqc_trans_settings_t));
}

void xqc_conn_init_flow_ctl(xqc_connection_t *conn)
{
    xqc_conn_flow_ctl_t *flow_ctl = &conn->conn_flow_ctl;
    xqc_trans_settings_t * settings = & conn->local_settings;
    flow_ctl->fc_max_data_can_send = settings->max_data; //握手后替换为对端指定的值
    flow_ctl->fc_max_data_can_recv = settings->max_data;
    flow_ctl->fc_max_streams_bidi_can_send = settings->max_streams_bidi; //握手后替换为对端指定的值
    flow_ctl->fc_max_streams_bidi_can_recv = settings->max_streams_bidi;
    flow_ctl->fc_max_streams_uni_can_send = settings->max_streams_uni; //握手后替换为对端指定的值
    flow_ctl->fc_max_streams_uni_can_recv = settings->max_streams_uni;
    flow_ctl->fc_data_sent = 0;
    flow_ctl->fc_data_recved = 0;
    flow_ctl->fc_recv_windows_size = settings->max_data;
    flow_ctl->fc_last_window_update_time = 0;
}

xqc_connection_t *
xqc_conn_create(xqc_engine_t *engine,
                xqc_cid_t *dcid, xqc_cid_t *scid,
                xqc_conn_callbacks_t *callbacks,
                xqc_conn_settings_t *settings,
                void *user_data,
                xqc_conn_type_t type)
{
    if (type == XQC_CONN_TYPE_CLIENT && settings->proto_version == XQC_IDRAFT_INIT_VER) {
        return NULL;
    }

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
    xqc_hex_dump(xc->scid_str, scid->cid_buf, scid->cid_len);
    xc->scid_str[scid->cid_len * 2] = '\0';
    xqc_hex_dump(xc->dcid_str, dcid->cid_buf, dcid->cid_len);
    xc->dcid_str[dcid->cid_len * 2] = '\0';
    xc->engine = engine;
    xc->log = engine->log;
    xc->conn_callbacks = *callbacks;

    xc->conn_settings = *settings;
    xc->user_data = user_data;
    xc->version = ((type == XQC_CONN_TYPE_SERVER) ? XQC_IDRAFT_INIT_VER : settings->proto_version);
    xc->discard_vn_flag = 0;
    xc->conn_type = type;
    xc->conn_flag = 0;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xc->zero_rtt_count = 0;
    xc->conn_create_time = xqc_now();
    xc->handshake_complete_time = 0;
    xc->first_data_send_time = 0;
    xc->max_stream_id_bidi_remote = -1;
    xc->max_stream_id_uni_remote = -1;
    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_MAX_LEVEL; encrypt_level++) {
        xc->undecrypt_count[encrypt_level] = 0;
    }

    xc->conn_send_ctl = xqc_send_ctl_create(xc);
    if (xc->conn_send_ctl == NULL) {
        goto fail;
    }

    xqc_init_list_head(&xc->conn_write_streams);
    xqc_init_list_head(&xc->conn_read_streams);
    xqc_init_list_head(&xc->conn_closing_streams);
    xqc_init_list_head(&xc->conn_all_streams);
    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_MAX_LEVEL; encrypt_level++) {
        xqc_init_list_head(&xc->undecrypt_packet_in[encrypt_level]);
    }

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

    xc->passive_streams_hash = xqc_pcalloc(xc->conn_pool, sizeof(xqc_id_hash_table_t));
    if (xc->passive_streams_hash == NULL) {
        goto fail;
    }
    if (xqc_id_hash_init(xc->passive_streams_hash,
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

    for (xqc_pkt_num_space_t i = 0; i < XQC_PNS_N; i++) {
        memset(&xc->recv_record[i], 0, sizeof(xqc_recv_record_t));
        xqc_init_list_head(&xc->recv_record[i].list_head);
    }

    xqc_log(xc->log, XQC_LOG_DEBUG, "|success|scid:%s|dcid:%s|conn:%p|", xqc_scid_str(&xc->scid), xqc_dcid_str(&xc->dcid), xc);
    //xqc_conn_log(xc, XQC_LOG_DEBUG, "|create success|scid:%s|dcid:%s|",  xqc_scid_str(&xc->scid), xqc_dcid_str(&xc->dcid));
    return xc;

fail:
    if (xc != NULL) {
        xqc_conn_destroy(xc);
    }
    return NULL;
}


xqc_connection_t *
xqc_conn_server_create(xqc_engine_t *engine,
                       const struct sockaddr *local_addr,
                       socklen_t local_addrlen,
                       const struct sockaddr *peer_addr,
                       socklen_t peer_addrlen,
                       xqc_cid_t *dcid, xqc_cid_t *scid,
                       xqc_conn_callbacks_t *callbacks,
                       xqc_conn_settings_t *settings,
                       void *user_data)
{
    xqc_connection_t *conn;

    //暂时不生成新cid
    /*xqc_cid_t new_scid;
    *//* server generates it's own cid *//*
    if (xqc_generate_cid(engine, &new_scid) != XQC_OK) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to generate_cid|");
        return NULL;
    }*/

    conn = xqc_conn_create(engine, dcid, /*&new_scid,*/ scid,
                           callbacks,
                           settings,
                           user_data,
                           XQC_CONN_TYPE_SERVER);

    if (conn == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
        return NULL;
    }

    if(xqc_server_tls_initial(engine, conn, & engine->ssl_config) < 0){
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to tls_initial|");
        goto fail;
    }

    xqc_cid_copy(&conn->ocid, scid);
    xqc_memcpy(conn->local_addr, local_addr, local_addrlen);
    xqc_memcpy(conn->peer_addr, peer_addr, peer_addrlen);
    conn->local_addrlen = local_addrlen;
    conn->peer_addrlen = peer_addrlen;

    xqc_log(engine->log, XQC_LOG_DEBUG, "|server accept new conn|");

    if (engine->eng_callback.server_accept) {
        if(engine->eng_callback.server_accept(engine, conn, &conn->scid, user_data) < 0){
            xqc_log(engine->log, XQC_LOG_ERROR, "|server_accept callback return error|");
            goto fail;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }
    /* Do connection callback on alpn */

    return conn;

fail:
    xqc_conn_destroy(conn);
    return NULL;
}

void
xqc_conn_server_on_alpn(xqc_connection_t *conn)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|alpn_num:%d|", conn->tlsref.alpn_num);
    if (conn->tlsref.alpn_num == XQC_ALPN_HTTP3_NUM) {
        /* 接管传输层回调 */
        conn->stream_callbacks = h3_stream_callbacks;
        conn->conn_callbacks = h3_conn_callbacks;
    } else {
        conn->stream_callbacks = conn->engine->eng_callback.stream_callbacks;
    }
    /* Do callback */
    if (conn->conn_callbacks.conn_create_notify) {
        if (conn->conn_callbacks.conn_create_notify(conn, &conn->scid, conn->user_data)) {
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }
}

void
xqc_conn_destroy(xqc_connection_t *xc)
{
    if (!xc) {
        return;
    }

    if (xc->conn_flag & XQC_CONN_FLAG_TICKING) {
        xqc_log(xc->log, XQC_LOG_ERROR, "|in XQC_CONN_FLAG_TICKING|%p|", xc);
        xc->conn_state = XQC_CONN_STATE_CLOSED;
        return;
    }

    xqc_log(xc->log, XQC_LOG_REPORT, "|%p|srtt:%ui|retrans rate:%.4f|send_count:%ud|lost_count:%ud|tlp_count:%ud|recv_count:%ud|has_0rtt:%d|0rtt_accept:%d|token_ok:%d|handshake_time:%ui|first_send_delay:%ui|conn_persist:%ui|err:0x%xi|%s|",
            xc, xqc_send_ctl_get_srtt(xc->conn_send_ctl), xqc_send_ctl_get_retrans_rate(xc->conn_send_ctl),
            xc->conn_send_ctl->ctl_send_count, xc->conn_send_ctl->ctl_lost_count, xc->conn_send_ctl->ctl_tlp_count, xc->conn_send_ctl->ctl_recv_count,
            xc->conn_flag & XQC_CONN_FLAG_HAS_0RTT ? 1:0,
            xc->conn_flag & XQC_CONN_FLAG_0RTT_OK ? 1:0,
            xc->conn_type == XQC_CONN_TYPE_SERVER ? (xc->conn_flag & XQC_CONN_FLAG_TOKEN_OK ? 1:0) : (-1),
            (xc->handshake_complete_time > xc->conn_create_time) ? (xc->handshake_complete_time - xc->conn_create_time) : 0,
            (xc->first_data_send_time > xc->conn_create_time) ? (xc->first_data_send_time - xc->conn_create_time) : 0,
            xqc_now() - xc->conn_create_time,
            xc->conn_err,
            xqc_conn_addr_str(xc));

    if (xc->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP) {
        xqc_wakeup_pq_remove(xc->engine->conns_wait_wakeup_pq, xc);
        xc->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
    }

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    xqc_packet_in_t *packet_in;

    /* destroy streams, must before conn_close_notify */
    xqc_list_for_each_safe(pos, next, &xc->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_destroy_stream(stream);
    }

    if (xc->conn_callbacks.conn_close_notify && (xc->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST)) {
        xc->conn_callbacks.conn_close_notify(xc, &xc->scid, xc->user_data);
        xc->conn_flag &= ~XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_send_ctl_destroy(xc->conn_send_ctl);

    for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns < XQC_PNS_N; pns++) {
        xqc_recv_record_destroy(&xc->recv_record[pns]);
    }

    /* free streams hash */
    if (xc->streams_hash) {
        xqc_id_hash_release(xc->streams_hash);
        xc->streams_hash = NULL;
    }
    if (xc->passive_streams_hash) {
        xqc_id_hash_release(xc->passive_streams_hash);
        xc->passive_streams_hash = NULL;
    }

    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_MAX_LEVEL; encrypt_level++) {
        xqc_list_for_each_safe(pos, next, &xc->undecrypt_packet_in[encrypt_level]) {
            packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
            xqc_list_del_init(pos);
            xqc_packet_in_destroy(packet_in, xc);
        }
    }

    /* Remove from engine's conns_hash */
    if (xc->engine->conns_hash) {
        xqc_remove_conns_hash(xc->engine->conns_hash, xc, &xc->scid);
    }
    if (xc->engine->conns_hash_dcid && (xc->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
        xqc_remove_conns_hash(xc->engine->conns_hash_dcid, xc, &xc->dcid);
    }

    if(xc->xc_ssl){
        SSL_free(xc->xc_ssl);
        xc->xc_ssl = NULL;
    }
    xqc_tls_free_tlsref(xc);  //需要提到释放conn_pool之前

    /* free pool, 必须放到最后释放 */
    if (xc->conn_pool) {
        xqc_destroy_pool(xc->conn_pool);
    }

}

void xqc_conn_set_user_data(xqc_connection_t *conn,
                            void *user_data)
{
    conn->user_data = user_data;
}

struct sockaddr*
xqc_conn_get_peer_addr(xqc_connection_t *conn,
                          socklen_t *peer_addr_len)
{
    *peer_addr_len = conn->peer_addrlen;
    return (struct sockaddr*)conn->peer_addr;
}

struct sockaddr *
xqc_conn_get_local_addr(xqc_connection_t *conn,
                        socklen_t *local_addr_len)
{
    *local_addr_len = conn->local_addrlen;
    return (struct sockaddr*)conn->local_addr;
}

int xqc_conn_send_ping(xqc_engine_t *engine, xqc_cid_t *cid, void *user_data)
{
    xqc_connection_t *conn;
    int ret;
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return XQC_OK;
    }
    ret = xqc_write_ping_to_packet(conn, user_data);
    if (ret < 0) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|write ping error|");
        return ret;
    }
    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }
    xqc_engine_main_logic_internal(engine, conn);
    return XQC_OK;
}


int 
xqc_conn_send_burst_packets(xqc_connection_t * conn, xqc_list_head_t * head, int congest)
{
    struct iovec iov_array[XQC_MAX_SEND_MSG_ONCE];
    char enc_pkt_array[XQC_MAX_SEND_MSG_ONCE][XQC_PACKET_OUT_SIZE_EXT];
    int burst_can_send = 0;

    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_send_ctl_t *ctl = conn->conn_send_ctl;
    ssize_t ret;

    xqc_msec_t now = xqc_now();
    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (congest) {
            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                /* 优先级高的包一定在前面 */
                if (!xqc_send_ctl_can_send(conn, packet_out)) {
                    break;
                }

                if (xqc_pacing_is_on(&ctl->ctl_pacing)) {
                    if (!xqc_pacing_can_write(&ctl->ctl_pacing, ctl, conn, packet_out)) {
                        xqc_log(conn->log, XQC_LOG_DEBUG, "|pacing blocked|");
                        break;
                    }

                    if (xqc_pacing_is_on(&ctl->ctl_pacing) && (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)) {
                        xqc_pacing_on_packet_sent(&ctl->ctl_pacing, ctl, ctl->ctl_conn, packet_out);
                    }
                }
            }
        }

        iov_array[burst_can_send].iov_base = enc_pkt_array[burst_can_send];
        iov_array[burst_can_send].iov_len = XQC_PACKET_OUT_SIZE_EXT;

        //ret = xqc_do_encrypt_pkt_buf(conn, packet_out, iov_array[burst_can_send].iov_base, &iov_array[burst_can_send].iov_len);
        ret = xqc_conn_enc_packet(conn, packet_out, iov_array[burst_can_send].iov_base,
                                  &iov_array[burst_can_send].iov_len, now);
        if (ret < 0) {
            return ret;
        }

        burst_can_send++;

        if (burst_can_send >= XQC_MAX_SEND_MSG_ONCE) {
            burst_can_send = XQC_MAX_SEND_MSG_ONCE;
            break;
        }
    }

    if (burst_can_send == 0) {
        return burst_can_send;
    }

    ret = conn->engine->eng_callback.write_mmsg(xqc_conn_get_user_data(conn), iov_array, burst_can_send,
                                                (struct sockaddr *) conn->peer_addr, conn->peer_addrlen);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|error send mmsg|");
        if (ret == XQC_SOCKET_ERROR) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
            conn->conn_state = XQC_CONN_STATE_CLOSED;
        }
        return ret;
    }

    if (ret != burst_can_send) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|error send msg|");
    }

    int already_send = ret;
    int remove_count = 0;//remove from send
    xqc_list_for_each_safe(pos, next, head) {
        if (remove_count >= already_send) {
            break;
        }
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_send_ctl_on_packet_sent(conn->conn_send_ctl, packet_out, now);
        xqc_send_ctl_remove_send(&packet_out->po_list);
        packet_out->po_flag &= ~XQC_POF_ENCRYPTED; //pkt num no longer save
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
        } else {
            xqc_send_ctl_insert_free(pos, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
        }
        remove_count++;
    }


    return already_send;
}

void 
xqc_conn_send_packets_batch(xqc_connection_t *conn){
    xqc_send_ctl_t *ctl = conn->conn_send_ctl;
    ssize_t ret;

    xqc_list_head_t *head;
    head =  &ctl->ctl_send_packets_high_pri;

    int congest = 0; // 不过拥塞控制
    while(!(xqc_list_empty(head))){
        int send_burst_count = xqc_conn_send_burst_packets(conn, head, congest);
        if(send_burst_count != XQC_MAX_SEND_MSG_ONCE){
            break;
        }
    }

    head = &ctl->ctl_send_packets;
    congest = 1;
    while(!(xqc_list_empty(head))){
        int send_burst_count = xqc_conn_send_burst_packets(conn, head, congest);
        if(send_burst_count != XQC_MAX_SEND_MSG_ONCE){
            break;
        }
    }
    return;

}

void
xqc_conn_send_packets (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_send_ctl_t *ctl = conn->conn_send_ctl;
    ssize_t ret;

    /* 高优先级队列不受拥塞控制 */
    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets_high_pri) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

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
        } else {
            xqc_send_ctl_insert_free(pos, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
        }

    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            /* 优先级高的包一定在前面 */
            if (!xqc_send_ctl_can_send(conn, packet_out)) {
                break;
            }

            if (xqc_pacing_is_on(&ctl->ctl_pacing)) {
                if (!xqc_pacing_can_write(&ctl->ctl_pacing, ctl, conn, packet_out)) {
                    xqc_log(conn->log, XQC_LOG_DEBUG, "|pacing blocked|");
                    break;
                }

                if (xqc_pacing_is_on(&ctl->ctl_pacing) && (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)) {
                    xqc_pacing_on_packet_sent(&ctl->ctl_pacing, ctl, ctl->ctl_conn, packet_out);
                }
            }
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
        } else {
            xqc_send_ctl_insert_free(pos, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
        }

    }
}



int xqc_conn_enc_packet(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, char *enc_pkt, size_t * enc_pkt_len, 
    xqc_msec_t current_time)
{
    if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT && conn->engine->eng_type == XQC_ENGINE_CLIENT
        && packet_out->po_frame_types != XQC_FRAME_BIT_ACK) {
        xqc_gen_padding_frame(packet_out);
    }

    if((packet_out->po_flag & XQC_POF_ENCRYPTED) == 0){
        packet_out->po_pkt.pkt_num = conn->conn_send_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;
    }
    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);


    int ret = xqc_packet_encrypt_buf(conn, packet_out, enc_pkt, enc_pkt_len);
    if(ret < 0){
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return -XQC_EENCRYPT;
    }

    packet_out->po_sent_time = current_time;

    packet_out->po_flag &= XQC_POF_ENCRYPTED;

    return 0;
}



ssize_t
xqc_conn_send_one_packet (xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    ssize_t sent;

    if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT && conn->engine->eng_type == XQC_ENGINE_CLIENT
        && packet_out->po_frame_types != XQC_FRAME_BIT_ACK) {
        xqc_gen_padding_frame(packet_out);
    }

    /* generate packet number */
    packet_out->po_pkt.pkt_num = conn->conn_send_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns];
    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);

    if (xqc_packet_encrypt(conn, packet_out) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return -XQC_EENCRYPT;
    }


    //printf("packet_out: send data:%d, pkt_type=%d\n", packet_out->po_used_size,packet_out->po_pkt.pkt_type);
    //hex_print(packet_out->po_buf, packet_out->po_used_size);

    xqc_msec_t now = xqc_now();
    packet_out->po_sent_time = now;


    sent = conn->engine->eng_callback.write_socket(xqc_conn_get_user_data(conn), conn->enc_pkt, conn->enc_pkt_len,
            (struct sockaddr*)conn->peer_addr, conn->peer_addrlen);
    xqc_log(conn->log, XQC_LOG_INFO,
            "|<==|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|",
            conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(packet_out->po_frame_types), conn->conn_send_ctl->ctl_bytes_in_flight, now);
    if (sent != conn->enc_pkt_len) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|write_socket error|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|now:%ui|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types), now);

        if (sent == XQC_SOCKET_ERROR) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
            conn->conn_state = XQC_CONN_STATE_CLOSED;
        }

        return -XQC_ESOCKET;
    }
    conn->conn_send_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;
    xqc_send_ctl_on_packet_sent(conn->conn_send_ctl, packet_out, now);

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

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types));
        packet_out->po_flag |= XQC_POF_LOST;

        if (xqc_pacing_is_on(&conn->conn_send_ctl->ctl_pacing)) {
            if (!xqc_pacing_can_write(&conn->conn_send_ctl->ctl_pacing, conn->conn_send_ctl, conn, packet_out)) {
                xqc_log(conn->log, XQC_LOG_DEBUG, "|pacing blocked|");
                break;
            }

            if (xqc_pacing_is_on(&conn->conn_send_ctl->ctl_pacing) && (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)) {
                xqc_pacing_on_packet_sent(&conn->conn_send_ctl->ctl_pacing, conn->conn_send_ctl, conn->conn_send_ctl->ctl_conn, packet_out);
            }
        }

        ret = xqc_conn_send_one_packet(conn, packet_out);

        if (ret < 0) {
            return;
        }

//        if (xqc_pacing_is_on(&conn->conn_send_ctl->ctl_pacing) && (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)) {
//            xqc_pacing_on_packet_sent(&conn->conn_send_ctl->ctl_pacing, conn->conn_send_ctl, conn->conn_send_ctl->ctl_conn, packet_out);
//        }

        xqc_send_ctl_remove_lost(&packet_out->po_list);
        xqc_send_ctl_insert_unacked(packet_out,
                                    &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                    conn->conn_send_ctl);

    }
}



void
xqc_conn_retransmit_lost_packets_batch(xqc_connection_t *conn)
{
    xqc_list_head_t *head;
    int congest = 1; /* need congestion control */

    head = &conn->conn_send_ctl->ctl_lost_packets;
    while(!(xqc_list_empty(head))){
        int send_burst_count = xqc_conn_send_burst_packets(conn, head, congest);
        if(send_burst_count != XQC_MAX_SEND_MSG_ONCE){
            break;
        }
    }
}


void
xqc_conn_retransmit_unacked_crypto(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_pkt_num_space_t pns;
    ssize_t ret;

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_flag & XQC_POF_NO_RETRANS) {
                continue;
            }
            if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
                xqc_log(conn->log, XQC_LOG_DEBUG, "|pkt_type:%s|pkt_num:%ui|frame:%s|",
                        xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type), packet_out->po_pkt.pkt_num,
                        xqc_frame_type_2_str(packet_out->po_frame_types));
                packet_out->po_flag |= XQC_POF_LOST;
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
    ssize_t ret;

    /*xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ret = xqc_conn_send_one_packet(conn, packet_out);
            if (ret < 0) {
                return;
            }

            *//* move send list to unacked list *//*
            xqc_send_ctl_remove_send(&packet_out->po_list);
            xqc_send_ctl_insert_unacked(packet_out,
                                        &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                        conn->conn_send_ctl);
        }

        if (++cnt >= probe_num) {
            return;
        }
    }*/

    for (pns = XQC_PNS_INIT; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_flag & XQC_POF_NO_RETRANS) {
                continue;
            }
            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                packet_out->po_flag |= XQC_POF_TLP;
                xqc_log(conn->log, XQC_LOG_DEBUG,
                        "|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                        conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                        xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                        xqc_frame_type_2_str(packet_out->po_frame_types));
                ret = xqc_conn_send_one_packet(conn, packet_out);
                if (ret < 0) {
                    return;
                }

                if(pns >= XQC_PNS_01RTT){ //握手报文不能够受每次重传报文个数的限制，否则握手报文传输不完整，无法生成加密key，也没有办法回复ack
                    /* 重新插入尾部，保持unack队列里按pkt_num排序 */
                    xqc_send_ctl_remove_unacked(packet_out, conn->conn_send_ctl);
                    xqc_send_ctl_insert_unacked(packet_out,
                                                &conn->conn_send_ctl->ctl_unacked_packets[packet_out->po_pkt.pkt_pns],
                                                conn->conn_send_ctl);
                    if (++cnt >= probe_num) {
                        return;
                    }
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


int
xqc_conn_close(xqc_engine_t *engine, xqc_cid_t *cid)
{
    int ret;
    xqc_connection_t *conn;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|state:%s|flag:%s|", conn,
            xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag));

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }

    ret = xqc_conn_immediate_close(conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_immediate_close error|ret:%d|", ret);
        return ret;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_engine_main_logic_internal(conn->engine, conn);

    return XQC_OK;
}

int xqc_conn_get_errno(xqc_connection_t *conn)
{
    return conn->conn_err;
}

int
xqc_conn_immediate_close(xqc_connection_t *conn)
{
    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }
    int ret;
    xqc_send_ctl_t *ctl;
    xqc_msec_t now;

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        conn->conn_state = XQC_CONN_STATE_CLOSING;

        xqc_send_ctl_drop_packets(conn->conn_send_ctl);

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

    if (conn->conn_close_count < 3) {
        ret = xqc_write_conn_close_to_packet(conn, conn->conn_err);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_conn_close_to_packet error|ret:%d|", ret);
        }
        ++conn->conn_close_count;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|gen_conn_close|state:%s|", xqc_conn_state_2_str(conn->conn_state));
    }

    return XQC_OK;
}

int
xqc_conn_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid, void *user_data,
                    const struct sockaddr *peer_addr,
                    socklen_t peer_addrlen)
{
    unsigned char buf[XQC_PACKET_OUT_SIZE];
    int size;

    size = (int)xqc_gen_reset_packet(dcid, buf);
    if (size < 0) {
        return size;
    }

    size = (int)engine->eng_callback.write_socket(user_data, buf, (size_t)size,
            peer_addr, peer_addrlen);
    if (size < 0) {
        return size;
    }

    xqc_log(engine->log, XQC_LOG_INFO, "|<==|xqc_conn_send_reset ok|size:%d|", size);
    return XQC_OK;
}

int
xqc_conn_send_retry(xqc_connection_t *conn, unsigned char *token, unsigned token_len)
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

    size = (int)engine->eng_callback.write_socket(xqc_conn_get_user_data(conn), buf, (size_t)size,
            (struct sockaddr*)conn->peer_addr, conn->peer_addrlen);
    if (size < 0) {
        return size;
    }

    xqc_log(engine->log, XQC_LOG_INFO, "|<==|xqc_conn_send_retry ok|size:%d|", size);
    return XQC_OK;
}



/*
 * 版本检查
 * */
int
xqc_conn_version_check(xqc_connection_t *c, uint32_t version)
{
    xqc_engine_t* engine = c->engine;
    int i = 0;

    if (engine->eng_type == XQC_ENGINE_SERVER) {
        uint32_t *list = engine->config->support_version_list;
        uint32_t count = engine->config->support_version_count;
        if (xqc_uint32_list_find(list, count, version) == -1) {
            // xqc_conn_send_version_negotiation(c); /*发送version negotiation*/
            return -XQC_EPROTO;
        }

        for (i = 0; i < XQC_IDRAFT_VER_NEGOTIATION; i++) {
            if (xqc_proto_version_value[i] == version) {
                c->version = i;
                return XQC_OK;
            }
        }

        return -XQC_EPROTO;
    }

    return XQC_OK;
}


#if (XQC_VERSION_NEGOTIATION)

/*
 * 发送版本协商协议
 * */
int
xqc_conn_send_version_negotiation(xqc_connection_t *c)
{
    xqc_packet_out_t *packet_out = xqc_packet_out_get(c->conn_send_ctl, XQC_PTYPE_VERSION_NEGOTIATION);
    if (packet_out == NULL) {
        return -XQC_EWRITE_PKT;
    }

    unsigned char* p = packet_out->po_buf;
    /*first byte*/
    *p++ = (1 << 7);

    /*version*/
    *(uint32_t*)p = 0;
    p += sizeof(uint32_t);

    /*DCIL(4)|SCIL(4)*/
    *p = (c->scid.cid_len - 3) << 4;
    *p |= c->dcid.cid_len - 3;
    ++p;

    /*dcid*/
    memcpy(p, c->scid.cid_buf, c->scid.cid_len);
    p += c->scid.cid_len;

    /*scid*/
    memcpy(p, c->dcid.cid_buf, c->dcid.cid_len);
    p += c->dcid.cid_len;

    /*supported version list*/
    uint32_t* version_list = c->engine->config->support_version_list;
    uint32_t version_count = c->engine->config->support_version_count;

    unsigned char* end = packet_out->po_buf + packet_out->po_buf_size;

    for (size_t i = 0; i < version_count; ++i) {
        if (p + sizeof(uint32_t) <= end) {
            *(uint32_t*)p = version_list[i];
            p += sizeof(uint32_t);
        } else {
            break;
        }
    }

    /*填充0*/
    memset(p, 0, end - p);

    /*设置used size*/
    packet_out->po_used_size = packet_out->po_buf_size;

    /*push to conns queue*/
    if (!(c->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(c->engine->conns_active_pq, c, c->last_ticked_time)) {
            c->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    return XQC_OK;
}

#endif /* XQC_VERSION_NEGOTIATION */


int
xqc_conn_continue_send(xqc_engine_t *engine, xqc_cid_t *cid)
{
    xqc_connection_t *conn;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    xqc_log(conn->log, XQC_LOG_INFO, "|conn:%p|", conn);
    if (engine->eng_callback.write_mmsg) {
        xqc_conn_send_packets_batch(conn);
    } else {
        xqc_conn_send_packets(conn);
    }
    xqc_engine_main_logic_internal(conn->engine, conn);

    return XQC_OK;
}

xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine,
                                    xqc_cid_t *cid)
{
    xqc_connection_t *conn;
    xqc_send_ctl_t *ctl;
    xqc_conn_stats_t conn_stats;
    xqc_memzero(&conn_stats, sizeof(conn_stats));
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return conn_stats;
    }
    ctl = conn->conn_send_ctl;
    conn_stats.lost_count = ctl->ctl_lost_count;
    conn_stats.send_count = ctl->ctl_send_count;
    conn_stats.tlp_count = ctl->ctl_tlp_count;
    conn_stats.recv_count = ctl->ctl_recv_count;
    conn_stats.srtt = ctl->ctl_srtt;
    conn_stats.conn_err = (int)conn->conn_err;
    conn_stats.early_data_flag = XQC_0RTT_NONE;
    if (conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT) {
        if (conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) {
            conn_stats.early_data_flag = XQC_0RTT_ACCEPT;
        } else if (conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ) {
            conn_stats.early_data_flag = XQC_0RTT_REJECT;
        }
    }
    xqc_recv_record_print(conn, &conn->recv_record[XQC_PNS_01RTT], conn_stats.ack_info, sizeof(conn_stats.ack_info));
    return conn_stats;
}

int
xqc_conn_check_token(xqc_connection_t *conn, const unsigned char *token, unsigned token_len)
{
    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|%ud exceed XQC_MAX_TOKEN_LEN|", token_len);
        return XQC_ERROR;
    }
    if (token_len == 0) {
        xqc_log(conn->log, XQC_LOG_INFO, "|token empty|");
        return XQC_ERROR;
    }
    /*printf("xqc_conn_check_token token:\n");
    hex_print((char *)token,token_len);*/

    struct sockaddr *sa = (struct sockaddr *)conn->peer_addr;
    const unsigned char *pos = token;
    if (*pos++ & 0x80) {
        struct in6_addr *in6 = (struct in6_addr *)pos;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)sa;
        if (token_len != 21) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|token_len error|token_len:%ui|", token_len);
            return XQC_ERROR;
        }
        if (memcmp(&sa6->sin6_addr, in6, sizeof(struct in6_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|ipv6 not match|");
            return XQC_ERROR;
        }
        pos += sizeof(struct in6_addr);

    } else {
        struct in_addr *in4 = (struct in_addr *)pos;
        struct sockaddr_in *sa4 = (struct sockaddr_in*)sa;
        if (token_len != 9) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|token_len error|token_len:%ui|", token_len);
            return XQC_ERROR;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|peer_addr:%s|", inet_ntoa(sa4->sin_addr));

        if (memcmp(&sa4->sin_addr, pos, sizeof(struct in_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|ipv4 not match|token_addr:%s|", inet_ntoa(*in4));
            return XQC_ERROR;
        }
        pos += sizeof(struct in_addr);
    }

    uint32_t *expire = (uint32_t*)pos;
    *expire = ntohl(*expire);

    xqc_msec_t now = xqc_now() / 1000000;
    if (*expire < now) {
        xqc_log(conn->log, XQC_LOG_INFO, "|token_expire|expire:%ud|now:%ui|", *expire, now);
        return XQC_ERROR;
    }
    else if (*expire - now <= XQC_TOKEN_UPDATE_DELTA) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|new token|expire:%ud|now:%ui|delta:%ud|", *expire, now, XQC_TOKEN_UPDATE_DELTA);
        xqc_write_new_token_to_packet(conn);
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|pass|");
    return XQC_OK;
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
    xqc_log(conn->log, XQC_LOG_DEBUG, "|expire:%ud|", expire);
    expire = htonl(expire);
    memcpy(token, &expire, sizeof(expire));
}

int
xqc_conn_early_data_reject(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;

    conn->conn_flag |= XQC_CONN_FLAG_0RTT_REJ;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|reject|");

    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        xqc_packet_in_t *packet_in;
        xqc_list_for_each_safe(pos, next, &conn->undecrypt_packet_in[XQC_ENC_LEV_0RTT]) {
            packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
            xqc_list_del_init(pos);
            xqc_packet_in_destroy(packet_in, conn);
        }
        return XQC_OK;
    }

    xqc_send_ctl_drop_0rtt_packets(conn->conn_send_ctl);

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        if (stream->stream_flag & XQC_STREAM_FLAG_HAS_0RTT) {
            stream->stream_send_offset = 0;
            stream->stream_unacked_pkt = 0;
            if (stream->stream_state_send >= XQC_SEND_STREAM_ST_RESET_SENT ||
                stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD) {
                xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);
                return XQC_OK;
            }
            stream->stream_state_send = XQC_SEND_STREAM_ST_READY;
            stream->stream_state_recv = XQC_RECV_STREAM_ST_RECV;
            xqc_stream_write_buffed_data_to_packets(stream);
        }
    }
    return XQC_OK;
}

int
xqc_conn_early_data_accept(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;

    conn->conn_flag |= XQC_CONN_FLAG_0RTT_OK;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|accept|");

    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        return XQC_OK;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);
    }
    return XQC_OK;
}

int
xqc_conn_handshake_complete(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    /* update flow control */
    conn->conn_flow_ctl.fc_max_data_can_send = conn->remote_settings.max_data;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = conn->remote_settings.max_streams_bidi;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = conn->remote_settings.max_streams_uni;

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_stream_set_flow_ctl(stream);
    }

    /* 0RTT rejected, send in 1RTT again */
    if (conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED &&
        ((conn->conn_type == XQC_CONN_TYPE_CLIENT && conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT)
         || conn->conn_type == XQC_CONN_TYPE_SERVER) &&
        !(conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) &&
        !(conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ)) {

        int accept = xqc_tls_is_early_data_accepted(conn);
        if (accept == XQC_TLS_EARLY_DATA_REJECT) {
            xqc_conn_early_data_reject(conn);
        } else if (accept == XQC_TLS_EARLY_DATA_ACCEPT) {
            xqc_conn_early_data_accept(conn);
        }
    }

#ifdef XQC_PRINT_SECRET
    unsigned char secret_str[3 * SECRET_TYPE_NUM * XQC_SECRET_HEX_MAX];
    int n_write = 0;
    secret_str[0] = '\n';
    n_write += 1;
    for (xqc_secret_type_t i = CLIENT_EARLY_TRAFFIC_SECRET; i < SECRET_TYPE_NUM; i++) {
        n_write += snprintf(secret_str + n_write, sizeof(secret_str), "%s %s %s\n", xqc_secret_type_2_str[i], conn->client_ramdom_hex, conn->secret_hex[i]);
    }
    xqc_log(conn->log, XQC_LOG_REPORT, "|print secret|%s|", secret_str);
#endif
    return XQC_OK;
}

int
xqc_conn_buff_undecrypt_packet_in(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level)
{
    if (conn->undecrypt_count[encrypt_level] >= XQC_UNDECRYPT_PACKET_MAX) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|delay|exceed XQC_UNDECRYPT_PACKET_MAX|undecrypt_count:%ud|encrypt_level:%d|",
                conn->undecrypt_count[encrypt_level], encrypt_level);
        return -1;
    }
    xqc_packet_in_t *new_packet = xqc_calloc(1, sizeof(xqc_packet_in_t));
    new_packet->pi_pkt = packet_in->pi_pkt;
    new_packet->buf = xqc_malloc(XQC_MSS); //按照MSS申请
    new_packet->buf_size = packet_in->buf_size;
    xqc_memcpy((unsigned char *)new_packet->buf, packet_in->buf, packet_in->buf_size);
    new_packet->pos = (unsigned char *)new_packet->buf + (packet_in->pos - packet_in->buf);
    new_packet->last = (unsigned char *)new_packet->buf + (packet_in->last - packet_in->buf);
    new_packet->pkt_recv_time = packet_in->pkt_recv_time;

    xqc_list_add_tail(&new_packet->pi_list, &conn->undecrypt_packet_in[encrypt_level]);
    conn->undecrypt_count[encrypt_level]++;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|====>|delay|undecrypt_count:%ud|encrypt_level:%d|", conn->undecrypt_count[encrypt_level], encrypt_level);
    return XQC_OK;
}

int
xqc_conn_process_undecrypt_packet_in(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level)
{
    if (conn->undecrypt_count[encrypt_level] == 0) {
        return XQC_OK;
    }
    xqc_packet_in_t *packet_in;
    xqc_list_head_t *pos, *next;
    int ret;
    xqc_list_for_each_safe(pos, next, &conn->undecrypt_packet_in[encrypt_level]) {
        packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|delay|undecrypt_count:%ud|encrypt_level:%d|",
                conn->undecrypt_count[encrypt_level], encrypt_level);
        ret = xqc_packet_process(conn, packet_in->buf, packet_in->buf_size, packet_in->pkt_recv_time);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_packet_process error|ret:%d|", ret);
            XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
            return ret;
        }
        xqc_list_del_init(pos);
        xqc_packet_in_destroy(packet_in, conn);
        conn->undecrypt_count[encrypt_level]--;
    }

    return XQC_OK;
}

void
xqc_conn_buff_1rtt_packets(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_SHORT_HEADER) {
            xqc_send_ctl_remove_send(&packet_out->po_list);
            xqc_send_ctl_insert_buff(&packet_out->po_list, &conn->conn_send_ctl->ctl_buff_1rtt_packets);
            if (!(conn->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
                packet_out->po_flag |= XQC_POF_DCID_NOT_DONE;
            }
        }
    }
}

void
xqc_conn_write_buffed_1rtt_packets(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        xqc_send_ctl_t *ctl = conn->conn_send_ctl;
        xqc_list_head_t *pos, *next;
        xqc_packet_out_t *packet_out;
        unsigned total = 0;
        xqc_list_for_each_safe(pos, next, &ctl->ctl_buff_1rtt_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            xqc_send_ctl_remove_buff(pos, ctl);
            xqc_send_ctl_insert_send(pos, &ctl->ctl_send_packets, ctl);
            if (packet_out->po_flag & XQC_POF_DCID_NOT_DONE) {
                xqc_short_packet_update_dcid(packet_out, conn);
            }
            ++total;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|total:%ui|", total);
    }
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

    xqc_log(conn->log, XQC_LOG_DEBUG, "|wakeup_time:%ui|", wakeup_time);

    return wakeup_time;
}

static char g_local_addr_str[INET6_ADDRSTRLEN];
static char g_peer_addr_str[INET6_ADDRSTRLEN];
//static char g_addr_str[2*(XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];

char *
xqc_conn_local_addr_str(const struct sockaddr *local_addr,
                        socklen_t local_addrlen)
{
    if (local_addrlen == 0 || local_addr == NULL) {
        g_local_addr_str[0] = '\0';
        return g_local_addr_str;
    }
    struct sockaddr_in *sa_local = (struct sockaddr_in *)local_addr;
    if (sa_local->sin_family == AF_INET) {
        if (inet_ntop(sa_local->sin_family, &sa_local->sin_addr, g_local_addr_str, local_addrlen) == NULL) {
            g_local_addr_str[0] = '\0';
        }
    } else {
        if (inet_ntop(sa_local->sin_family, &((struct sockaddr_in6*)sa_local)->sin6_addr, g_local_addr_str, local_addrlen) == NULL) {
            g_local_addr_str[0] = '\0';
        }
    }
    return g_local_addr_str;
}

char *
xqc_conn_peer_addr_str(const struct sockaddr *peer_addr,
                       socklen_t peer_addrlen)
{
    if (peer_addrlen == 0 || peer_addr == NULL) {
        g_peer_addr_str[0] = '\0';
        return g_peer_addr_str;
    }
    struct sockaddr_in *sa_peer = (struct sockaddr_in *)peer_addr;
    if (sa_peer->sin_family == AF_INET) {
        if (inet_ntop(sa_peer->sin_family, &sa_peer->sin_addr, g_peer_addr_str, peer_addrlen) == NULL) {
            g_peer_addr_str[0] = '\0';
        }
    } else {
        if (inet_ntop(sa_peer->sin_family, &((struct sockaddr_in6*)sa_peer)->sin6_addr, g_peer_addr_str, peer_addrlen) == NULL) {
            g_peer_addr_str[0] = '\0';
        }
    }
    return g_peer_addr_str;
}

char *
xqc_conn_addr_str(xqc_connection_t *conn)
{
    if (conn->addr_str_len == 0) {
        struct sockaddr_in *sa_local = (struct sockaddr_in *)conn->local_addr;
        struct sockaddr_in *sa_peer = (struct sockaddr_in *)conn->peer_addr;

        conn->addr_str_len = snprintf(conn->addr_str, sizeof(conn->addr_str), "l-%s-%d-%s p-%s-%d-%s",
             xqc_conn_local_addr_str((struct sockaddr*)sa_local, conn->local_addrlen), ntohs(sa_local->sin_port), xqc_scid_str(&conn->scid),
             xqc_conn_peer_addr_str((struct sockaddr*)sa_peer, conn->peer_addrlen), ntohs(sa_peer->sin_port), xqc_dcid_str(&conn->dcid));
    }

    return conn->addr_str;
}


