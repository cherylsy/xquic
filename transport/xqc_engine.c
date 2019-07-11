
#include "xqc_engine.h"
#include "xqc_transport.h"
#include <common/xqc_errno.h>
#include "../include/xquic.h"
#include "../common/xqc_str.h"
#include "../common/xqc_random.h"
#include "../common/xqc_priority_q.h"
#include "../common/xqc_str_hash.h"
#include "../common/xqc_timer.h"
#include "../common/xqc_hash.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_packet_in.h"
#include "xqc_packet.h"
#include "xqc_cid.h"
#include "xqc_wakeup_pq.h"


xqc_config_t *
xqc_engine_config_create(xqc_engine_type_t engine_type)
{
    xqc_config_t *config = xqc_malloc(sizeof(xqc_config_t));
    if (config == NULL) {
        return NULL;
    }

    xqc_memzero(config, sizeof(xqc_config_t));

    /* set default value */
    config->conn_pool_size = 4096;

    if (engine_type == XQC_ENGINE_SERVER) {
        config->streams_hash_bucket_size = 127;
        config->conns_hash_bucket_size = 127;
        config->conns_pq_capacity = 127;
    } else if (engine_type == XQC_ENGINE_CLIENT) { //TODO: confirm the value
        config->streams_hash_bucket_size = 8;
        config->conns_hash_bucket_size = 8;
        config->conns_pq_capacity = 8;
    }

    config->support_version_count = 1;
    config->support_version_list[0] = XQC_QUIC_VERSION;

    return config;
}

void 
xqc_engine_config_destroy(xqc_config_t *config)
{
    xqc_free(config);
}

xqc_str_hash_table_t *
xqc_engine_conns_hash_create(xqc_config_t *config)
{
    xqc_str_hash_table_t *hash_table = xqc_malloc(sizeof(xqc_str_hash_table_t));
    if (hash_table == NULL) {
        return NULL;
    }

    if (xqc_str_hash_init(hash_table, xqc_default_allocator, config->conns_hash_bucket_size)) {
        goto fail;
    }

    return hash_table;

fail:
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
    return NULL;
}

void
xqc_engine_conns_hash_destroy(xqc_str_hash_table_t *hash_table)
{
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
}

xqc_pq_t *
xqc_engine_conns_pq_create(xqc_config_t *config)
{
    xqc_pq_t *q = xqc_malloc(sizeof(xqc_pq_t));
    if (q == NULL) {
        return NULL;
    }

    xqc_memzero(q, sizeof(xqc_pq_t));

    if (xqc_pq_init(q, sizeof(xqc_conns_pq_elem_t), config->conns_pq_capacity,
                    xqc_default_allocator, xqc_pq_revert_cmp)) {
        goto fail;
    }

    return q;

fail:
    xqc_pq_destroy(q);
    xqc_free(q);
    return NULL;
}

xqc_wakeup_pq_t *
xqc_engine_wakeup_pq_create(xqc_config_t *config)
{
    xqc_wakeup_pq_t *q = xqc_malloc(sizeof(xqc_wakeup_pq_t));
    if (q == NULL) {
        return NULL;
    }

    xqc_memzero(q, sizeof(xqc_wakeup_pq_t));

    if (xqc_wakeup_pq_init(q, config->conns_pq_capacity,
                    xqc_default_allocator, xqc_wakeup_pq_revert_cmp)) {
        goto fail;
    }

    return q;

    fail:
    xqc_wakeup_pq_destroy(q);
    xqc_free(q);
    return NULL;
}



xqc_connection_t *
xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *cid, char type)
{
    if (cid == NULL || cid->cid_len == 0 || cid->cid_buf == NULL) {
        return NULL;
    }

    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str;
    str.data = cid->cid_buf;
    str.len = cid->cid_len;

    if (type == 's') {
        return xqc_str_hash_find(engine->conns_hash, hash, str);
    } else {
        return xqc_str_hash_find(engine->conns_hash_dcid, hash, str);
    }
}


void
xqc_engine_conns_pq_destroy(xqc_pq_t *q)
{
    xqc_pq_destroy(q);
    xqc_free(q);
}

void
xqc_engine_wakeup_pq_destroy(xqc_wakeup_pq_t *q)
{
    xqc_wakeup_pq_destroy(q);
    xqc_free(q);
}

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *
xqc_engine_create(xqc_engine_type_t engine_type)
{
    xqc_engine_t *engine = NULL;

    engine = xqc_malloc(sizeof(xqc_engine_t));
    if (engine == NULL) {
        goto fail;
    }
    xqc_memzero(engine, sizeof(xqc_engine_t));

    engine->eng_type = engine_type;

    engine->config = xqc_engine_config_create(engine_type);
    if (engine->config == NULL) {
        goto fail;
    }

    if (engine_type == XQC_ENGINE_SERVER) {
        engine->log = xqc_log_init(XQC_LOG_DEBUG, "./", "slog");
    } else {
        engine->log = xqc_log_init(XQC_LOG_DEBUG, "./", "clog");
    }
    if (engine->log == NULL) {
        goto fail;
    }
    
    engine->rand_generator = xqc_random_generator_create(engine->log);
    if (engine->rand_generator == NULL) {
        goto fail;
    }

    engine->conns_hash = xqc_engine_conns_hash_create(engine->config);
    if (engine->conns_hash == NULL) {
        goto fail;
    }
    engine->conns_hash_dcid = xqc_engine_conns_hash_create(engine->config);
    if (engine->conns_hash_dcid == NULL) {
        goto fail;
    }

    engine->conns_pq = xqc_engine_conns_pq_create(engine->config);
    if (engine->conns_pq == NULL) {
        goto fail;
    }

    engine->conns_wakeup_pq = xqc_engine_wakeup_pq_create(engine->config);
    if (engine->conns_wakeup_pq == NULL) {
        goto fail;
    }

    return engine;

fail:
    xqc_engine_destroy(engine);
    return NULL;
}


void 
xqc_engine_destroy(xqc_engine_t *engine)
{
    xqc_connection_t *conn;

    if (engine == NULL) {
        return;
    }

    if (engine->config) {
        xqc_engine_config_destroy(engine->config);
        engine->config = NULL;
    }

    if (engine->log) {
        xqc_free(engine->log);
        engine->log = NULL;
    }

    if (engine->rand_generator) {
        xqc_random_generator_destroy(engine->rand_generator);
        engine->rand_generator = NULL;
    }

    if (engine->conns_hash) {
        xqc_engine_conns_hash_destroy(engine->conns_hash);
        engine->conns_hash = NULL;
    }
    if (engine->conns_hash_dcid) {
        xqc_engine_conns_hash_destroy(engine->conns_hash_dcid);
        engine->conns_hash_dcid = NULL;
    }

    while (!xqc_pq_empty(engine->conns_pq)) {
        xqc_conns_pq_elem_t *el = xqc_conns_pq_top(engine->conns_pq);
        xqc_conns_pq_pop(engine->conns_pq);
        if (el == NULL || el->conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_engine_destroy|NULL ptr, skip");
            continue;
        }
        conn = el->conn;
        if (conn->conn_flag & XQC_CONN_FLAG_WAKEUP) {
            xqc_wakeup_pq_remove(engine->conns_wakeup_pq, conn);
            conn->conn_flag &= ~XQC_CONN_FLAG_WAKEUP;
        }
        xqc_destroy_connection(conn);
    }

    while (!xqc_wakeup_pq_empty(engine->conns_wakeup_pq)) {
        xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wakeup_pq);
        xqc_wakeup_pq_pop(engine->conns_wakeup_pq);
        if (el == NULL || el->conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_engine_destroy|NULL ptr, skip");
            continue;
        }
        conn = el->conn;
        xqc_destroy_connection(conn);
    }

    if (engine->conns_pq) {
        xqc_engine_conns_pq_destroy(engine->conns_pq);
        engine->conns_pq = NULL;
    }
    if (engine->conns_wakeup_pq) {
        xqc_engine_wakeup_pq_destroy(engine->conns_wakeup_pq);
        engine->conns_wakeup_pq = NULL;
    }
    xqc_free(engine);
}


/**
 * Init engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
void 
xqc_engine_init (xqc_engine_t *engine,
                 xqc_engine_callback_t engine_callback,
                 void *event_timer)
{
    xqc_engine_set_callback(engine, engine_callback);
    engine->event_timer = event_timer;
}

void
xqc_engine_set_callback (xqc_engine_t *engine,
                              xqc_engine_callback_t engine_callback)
{
    engine->eng_callback = engine_callback;
}

xqc_msec_t
xqc_engine_wakeup_after (xqc_engine_t *engine)
{
    xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wakeup_pq);
    if (el) {
        xqc_msec_t now = xqc_gettimeofday();

        return el->wakeup_time > now ? el->wakeup_time - now : 1;
    }


    return 0;
}

#define XQC_CHECK_IMMEDIATE_CLOSE() do {                        \
    if (conn->conn_flag & XQC_CONN_IMMEDIATE_CLOSE_FLAGS) {     \
        xqc_conn_immediate_close(conn);                         \
        goto end;                                               \
    }                                                           \
} while(0);                                                     \

void
xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_engine_process_conn|conn=%p, state=%s, flag=%s, now=%ui",
            conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

    int ret;

    xqc_send_ctl_timer_expire(conn->conn_send_ctl, now);

    if (conn->conn_flag & XQC_CONN_FLAG_TIME_OUT) {
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return;
    }

    if (conn->conn_state < XQC_CONN_STATE_ESTABED) {
        xqc_process_crypto_read_streams(conn);
        xqc_process_crypto_write_streams(conn);
    }

    XQC_CHECK_IMMEDIATE_CLOSE();

    xqc_process_buff_packets(conn);
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) {
        xqc_process_read_streams(conn);
        if (xqc_send_ctl_can_write(conn->conn_send_ctl)) {
            xqc_process_write_streams(conn);
        }
    }

    XQC_CHECK_IMMEDIATE_CLOSE();

    if (xqc_should_generate_ack(conn)) {
        ret = xqc_write_ack_to_packets(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets error");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }

    XQC_CHECK_IMMEDIATE_CLOSE();

    /*if (conn->conn_type == XQC_CONN_TYPE_SERVER && conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)
    {
        //for test
        xqc_remove_conns_hash(conn->engine->conns_hash, conn, &conn->scid);
    }*/
end:
    return;
}


/**
 * Process all connections
 */
void
xqc_engine_main_logic (xqc_engine_t *engine)
{
    xqc_msec_t now = xqc_gettimeofday();
    xqc_connection_t *conn;

    xqc_list_head_t closed_conns;
    xqc_list_head_t ticked_conns;
    xqc_list_head_t *pos, *next;
    xqc_init_list_head(&closed_conns);
    xqc_init_list_head(&ticked_conns);

    while (!xqc_wakeup_pq_empty(engine->conns_wakeup_pq)) {
        xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wakeup_pq);
        if (el == NULL || el->conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_engine_main_logic|NULL ptr, skip");
            xqc_wakeup_pq_pop(engine->conns_wakeup_pq);
            continue;
        }
        conn = el->conn;

        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_engine_main_logic wakeup|conn=%p, state=%s, flag=%s, now=%ui, wakeup=%ui",
                conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now, el->wakeup_time);
        if (el->wakeup_time <= now) {
            xqc_wakeup_pq_pop(engine->conns_wakeup_pq);
            conn->conn_flag &= ~XQC_CONN_FLAG_WAKEUP;

            if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
                if (0 == xqc_conns_pq_push(engine->conns_pq, conn, conn->last_ticked_time)) {
                    conn->conn_flag |= XQC_CONN_FLAG_TICKING;
                }
            }
        } else {
            break;
        }
    }

    while (!xqc_pq_empty(engine->conns_pq)) {
        xqc_conns_pq_elem_t *el = xqc_conns_pq_top(engine->conns_pq);
        if (el == NULL || el->conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_engine_main_logic|NULL ptr, skip");
            xqc_conns_pq_pop(engine->conns_pq);
            continue;
        }
        conn = el->conn;

        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_engine_main_logic ticking|conn=%p, state=%s, flag=%s, now=%ui",
                conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

        now = xqc_gettimeofday();
        xqc_engine_process_conn(conn, now);
        if (conn->conn_state == XQC_CONN_STATE_CLOSED) {
            xqc_list_add_tail(&conn->conn_list, &closed_conns);
        } else {
            conn->last_ticked_time = now;

            xqc_conn_retransmit_lost_packets(conn);
            xqc_conn_send_packets(conn);

            xqc_list_add_tail(&conn->conn_list, &ticked_conns);
        }

        xqc_conns_pq_pop(engine->conns_pq);
        conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    }

    xqc_list_for_each_safe(pos, next, &closed_conns) {
        conn = xqc_list_entry(pos, xqc_connection_t, conn_list);
        xqc_list_del_init(pos);
        xqc_destroy_connection(conn);
    }

    xqc_list_for_each_safe(pos, next, &ticked_conns) {
        conn = xqc_list_entry(pos, xqc_connection_t, conn_list);

        xqc_list_del_init(pos);

        conn->next_tick_time = xqc_conn_next_wakeup_time(conn);

        if (/*tickable*/0) {
            if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
                if (0 == xqc_conns_pq_push(engine->conns_pq, conn, conn->last_ticked_time)) {
                    conn->conn_flag |= XQC_CONN_FLAG_TICKING;
                }
            }
        }

        if (conn->next_tick_time) {
            if (!(conn->conn_flag & XQC_CONN_FLAG_WAKEUP)) {
                xqc_wakeup_pq_push(engine->conns_wakeup_pq, conn->next_tick_time, conn);
                conn->conn_flag |= XQC_CONN_FLAG_WAKEUP;
            }
            else {
                //remove from pq then push again, update wakeup time
                xqc_wakeup_pq_remove(engine->conns_wakeup_pq, conn);
                xqc_wakeup_pq_push(engine->conns_wakeup_pq, conn->next_tick_time, conn);
                conn->conn_flag |= XQC_CONN_FLAG_WAKEUP;
            }
        } else {
            /* 至少会有idle定时器，这是异常分支 */
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_engine_main_logic|destroy_connection");
            xqc_destroy_connection(conn);
        }
    }

    xqc_msec_t wake_after = xqc_engine_wakeup_after(engine);
    if (wake_after > 0 && engine->event_timer) {
        engine->eng_callback.set_event_timer(engine->event_timer, xqc_engine_wakeup_after(engine));
    }

    return;
}


/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in millisecond
 */
int xqc_engine_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time,
                               void *user_data)
{
    /* find connection with cid*/
    xqc_connection_t *conn = NULL;
    xqc_cid_t dcid, scid; //dcid:对端cid，scid:本地cid
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    int ret = 0;

    /* 对端的scid是本地的dcid */
    if (xqc_packet_parse_cid(&scid, &dcid, (unsigned char *)packet_in_buf, packet_in_size) != XQC_OK) {
        xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to parse cid");
        return -XQC_EILLPKT;
    }

    conn = xqc_engine_conns_hash_find(engine, &scid, 's');

    /* server creates connection when receiving a initial packet*/
    if (conn == NULL
            && engine->eng_type == XQC_ENGINE_SERVER
            && XQC_PACKET_IS_LONG_HEADER(packet_in_buf)
            &&
                (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_INIT
                || XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_0RTT)
            ) {

        /* 防止initial包重传重复创建连接 */
        conn = xqc_engine_conns_hash_find(engine, &dcid, 'd');
        if (conn) {
            goto process;
        }

        xqc_conn_type_t conn_type = (engine->eng_type == XQC_ENGINE_SERVER) ?
                                     XQC_CONN_TYPE_SERVER : XQC_CONN_TYPE_CLIENT;

        /* server generates it's own cid */
        if (xqc_generate_cid(engine, &scid) != XQC_OK) {
            xqc_log(engine->log, XQC_LOG_ERROR, "packet_process: fail to generate_cid");
            return -XQC_ESYS;
        }
        memset(&scid.cid_buf, 0xDD, 4); //TODO: for test
        conn = xqc_create_connection(engine, &dcid, &scid,
                                     &(engine->eng_callback.conn_callbacks), 
                                     engine->settings, user_data,
                                     conn_type);

        if (conn == NULL) {
            xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to create connection");
            return -XQC_ENULLPTR;
        }

        xqc_log(engine->log, XQC_LOG_DEBUG, "xqc_engine_packet_process: server accept new conn");
    }
    if (conn == NULL) {
        if (!xqc_is_reset_packet(&scid, packet_in_buf, packet_in_size)) {
            xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to find connection, send reset");
            ret = xqc_send_reset(engine, &scid, user_data);
            if (ret) {
                xqc_log(engine->log, XQC_LOG_ERROR, "packet_process: fail to send reset");
            }
        } else {
            //RST包只有对端cid
            conn = xqc_engine_conns_hash_find(engine, &scid, 'd');
            if (conn) {
                xqc_log(engine->log, XQC_LOG_WARN, "packet_process: receive reset, enter draining");
                if (conn->conn_state < XQC_CONN_STATE_DRAINING) {
                    conn->conn_state = XQC_CONN_STATE_DRAINING;
                    xqc_msec_t pto = xqc_send_ctl_calc_pto(conn->conn_send_ctl);
                    if (!xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_DRAINING)) {
                        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_DRAINING, 3 * pto + recv_time);
                    }
                }
                goto after_process;
            }
            xqc_log(engine->log, XQC_LOG_WARN, "packet_process: fail to find connection, exit");
        }
        return -XQC_ECONN_NFOUND;
    }

process:
    xqc_log(engine->log, XQC_LOG_INFO, "==> xqc_engine_packet_process conn=%p, size=%ui, state=%s",
            conn, packet_in_size, xqc_conn_state_2_str(conn->conn_state));

    /* process packets */
    ret = (int)xqc_conn_process_packets(conn, packet_in_buf, packet_in_size, recv_time);
    if (ret) {
        xqc_log(engine->log, XQC_LOG_ERROR, "packet_process: fail to process packets");
        XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
        goto after_process;
    }

    xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_IDLE,
                           recv_time + conn->conn_send_ctl->ctl_conn->trans_param.idle_timeout);


after_process:
    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(engine->conns_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        } else {
            xqc_log(engine->log, XQC_LOG_ERROR, "packet_process: xqc_conns_pq_push error");
            return -XQC_ESYS;
        }
    }

    /* main logic */
    xqc_engine_main_logic(engine);

    return ret;
}
