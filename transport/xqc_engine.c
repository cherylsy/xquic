
#include "xqc_engine.h"
#include "include/xquic.h"
#include "common/xqc_str.h"
#include "common/xqc_random.h"
#include "common/xqc_priority_q.h"
#include "common/xqc_str_hash.h"
#include "common/xqc_timer.h"
#include "common/xqc_hash.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_packet_in.h"
#include "xqc_packet.h"
#include "xqc_cid.h"
#include "xqc_wakeup_pq.h"
#include "crypto/xqc_tls_header.h"
#include "xqc_utils.h"
#include "http3/xqc_h3_qpack_token.h"

xqc_config_t default_client_config = {
        .conn_pool_size = 4096,
        .streams_hash_bucket_size = 1024,
        .conns_hash_bucket_size = 1024,
        .conns_active_pq_capacity = 128,
        .conns_wakeup_pq_capacity = 128,
        .support_version_count = 1,
        .support_version_list[0] = XQC_QUIC_VERSION,
        .cid_len = XQC_DEFAULT_CID_LEN,
};

xqc_config_t default_server_config = {
        .conn_pool_size = 4096,
        .streams_hash_bucket_size = 1024,
        .conns_hash_bucket_size = 1024*1024, //不能扩展，连接多了查找性能
        .conns_active_pq_capacity = 1024,
        .conns_wakeup_pq_capacity = 16*1024,
        .support_version_count = 1,
        .support_version_list[0] = XQC_QUIC_VERSION,
        .cid_len = XQC_DEFAULT_CID_LEN,
};

int
xqc_set_config(xqc_config_t *dst, const xqc_config_t *src)
{
    if (src->conn_pool_size > 0) {
        dst->conn_pool_size = src->conn_pool_size;
    }
    if (src->streams_hash_bucket_size > 0) {
        dst->streams_hash_bucket_size = src->streams_hash_bucket_size;
    }
    if (src->conns_hash_bucket_size > 0) {
        dst->conns_hash_bucket_size = src->conns_hash_bucket_size;
    }
    if (src->conns_active_pq_capacity > 0) {
        dst->conns_active_pq_capacity = src->conns_active_pq_capacity;
    }
    if (src->conns_wakeup_pq_capacity > 0) {
        dst->conns_wakeup_pq_capacity = src->conns_wakeup_pq_capacity;
    }
    if (src->support_version_count > 0 && src->support_version_count <= XQC_SUPPORT_VERSION_MAX) {
        dst->support_version_count = src->support_version_count;
        for (int i = 0; i < src->support_version_count; ++i) {
            dst->support_version_list[i] = src->support_version_list[i];
        }
    } else if (src->support_version_count > XQC_SUPPORT_VERSION_MAX) {
        return XQC_ERROR;
    }
    if (src->cid_len > 0 && src->cid_len <= XQC_MAX_CID_LEN) {
        dst->cid_len = src->cid_len;
    } else if (src->cid_len > XQC_MAX_CID_LEN) {
        return XQC_ERROR;
    }
    return XQC_OK;
}

int
xqc_set_engine_config(xqc_config_t *config, xqc_engine_type_t engine_type)
{
    if (engine_type == XQC_ENGINE_SERVER) {
        return xqc_set_config(&default_server_config, config);
    } else {
        return xqc_set_config(&default_client_config, config);
    }
}

xqc_config_t *
xqc_engine_config_create(xqc_engine_type_t engine_type)
{
    xqc_config_t *config = xqc_malloc(sizeof(xqc_config_t));
    if (config == NULL) {
        return NULL;
    }

    xqc_memzero(config, sizeof(xqc_config_t));

    if (engine_type == XQC_ENGINE_SERVER) {
        xqc_set_config(config, &default_server_config);
    } else if (engine_type == XQC_ENGINE_CLIENT) {
        xqc_set_config(config, &default_client_config);
    }

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

    if (xqc_pq_init(q, sizeof(xqc_conns_pq_elem_t), config->conns_active_pq_capacity,
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

    if (xqc_wakeup_pq_init(q, config->conns_wakeup_pq_capacity,
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
    if (cid == NULL || cid->cid_len == 0) {
        return NULL;
    }

    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str;
    str.data = cid->cid_buf;
    str.len = cid->cid_len;

    if (type == 's') {
        /* 本地cid */
        return xqc_str_hash_find(engine->conns_hash, hash, str);
    } else {
        /* 对端cid */
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

xqc_msec_t
xqc_engine_wakeup_after (xqc_engine_t *engine)
{
    xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq);
    if (el) {
        xqc_msec_t now = xqc_now();

        return el->wakeup_time > now ? el->wakeup_time - now : 1;
    }


    return 0;
}

int
xqc_engine_schedule_reset(xqc_engine_t *engine,
                          const struct sockaddr *peer_addr,
                          socklen_t peer_addrlen,
                          xqc_msec_t now)
{
    /* Can send 2 reset packets in 5 seconds */
    if (now - engine->reset_sent_cnt_cleared > 5000*1000) {
        memset(engine->reset_sent_cnt, 0, sizeof(engine->reset_sent_cnt));
        engine->reset_sent_cnt_cleared = now;
    }
    uint32_t hash = xqc_murmur_hash2((unsigned char*)peer_addr, peer_addrlen);
    hash = hash % XQC_RESET_CNT_ARRAY_LEN;
    xqc_log(engine->log, XQC_LOG_DEBUG, "|hash:%ud|cnt:%ud|",hash, engine->reset_sent_cnt[hash]);
    if (engine->reset_sent_cnt[hash] < 2) {
        engine->reset_sent_cnt[hash]++;
        return XQC_OK;
    }
    return XQC_ERROR;
}

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *
xqc_engine_create(xqc_engine_type_t engine_type,
                  xqc_engine_ssl_config_t * ssl_config,
                  xqc_engine_callback_t engine_callback,
                  void *user_data)
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

    xqc_engine_set_callback(engine, engine_callback);
    engine->user_data = user_data;

    engine->log = xqc_log_init(&engine->eng_callback.log_callbacks, engine->user_data);
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

    engine->conns_active_pq = xqc_engine_conns_pq_create(engine->config);
    if (engine->conns_active_pq == NULL) {
        goto fail;
    }

    engine->conns_wait_wakeup_pq = xqc_engine_wakeup_pq_create(engine->config);
    if (engine->conns_wait_wakeup_pq == NULL) {
        goto fail;
    }

    if (ssl_config != NULL) { //ssl_config null for test
        if (xqc_ssl_init_engine_config(engine, ssl_config, &engine->session_ticket_key) < 0) {
            goto fail;
        }

        engine->ssl_meth = xqc_create_bio_method();
        if(engine->ssl_meth == NULL){
            goto fail;
        }

        if (engine_type == XQC_ENGINE_SERVER) {
            engine->ssl_ctx = xqc_create_server_ssl_ctx(engine, ssl_config);
            if (engine->ssl_ctx == NULL) {
                goto fail;
            }
        } else {
            engine->ssl_ctx = xqc_create_client_ssl_ctx(engine, ssl_config);
            if (engine->ssl_ctx == NULL) {
                goto fail;
            }
        }
    } else {
        goto fail;
    }

    xqc_qpack_init_static_token_index();

    return engine;

fail:
    xqc_engine_destroy(engine);
    return NULL;
}

xqc_connection_t * xqc_conns_pq_pop_top_conn(xqc_pq_t *pq){ //遍历cons_pq队列用该函数。因为取出来后需要立即从堆中删除，否则发生push动作再pop就会发生错误
    xqc_conns_pq_elem_t *el = xqc_conns_pq_top(pq);
    if(XQC_UNLIKELY(el == NULL || el->conn == NULL)){
        xqc_conns_pq_pop(pq);
        return NULL;
    }

    xqc_connection_t * conn = el->conn;
    xqc_conns_pq_pop(pq);
    return conn;
}

void
xqc_engine_destroy(xqc_engine_t *engine)
{
    xqc_connection_t *conn;

    if (engine == NULL) {
        return;
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|begin|");

    /* 必须先释放连接，再释放其他结构 */
    if (engine->conns_active_pq) {
        while (!xqc_pq_empty(engine->conns_active_pq)) {
            conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
            if (conn == NULL) {
                xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                continue;
            }
            conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
            if (conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP) {
                xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
            }
            xqc_conn_destroy(conn);
        }
    }

    if (engine->conns_wait_wakeup_pq) {
        while (!xqc_wakeup_pq_empty(engine->conns_wait_wakeup_pq)) {
            xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq);
            if (el == NULL || el->conn == NULL) {
                xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);
                continue;
            }
            conn = el->conn; //必须先取值再pop，否则值会被修改
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq); // pop 操作需要紧跟top操作,中间不能有push动作

            conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
            xqc_conn_destroy(conn);
        }
    }

    if (engine->conns_active_pq) {
        xqc_engine_conns_pq_destroy(engine->conns_active_pq);
        engine->conns_active_pq = NULL;
    }
    if (engine->conns_wait_wakeup_pq) {
        xqc_engine_wakeup_pq_destroy(engine->conns_wait_wakeup_pq);
        engine->conns_wait_wakeup_pq = NULL;
    }

    if (engine->config) {
        xqc_engine_config_destroy(engine->config);
        engine->config = NULL;
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

    xqc_tls_free_engine_config(&engine->ssl_config);

    if(engine->ssl_ctx){
        SSL_CTX_free(engine->ssl_ctx);
    }
    if(engine->ssl_meth){
        BIO_meth_free(engine->ssl_meth);
    }

    if (engine->log) {
        xqc_log_release(engine->log);
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
                 void *user_data)
{
    xqc_engine_set_callback(engine, engine_callback);
    engine->user_data = user_data;
}

void
xqc_engine_set_callback (xqc_engine_t *engine,
                              xqc_engine_callback_t engine_callback)
{
    engine->eng_callback = engine_callback;
}

#define XQC_CHECK_UNDECRYPT_PACKETS() do {                      \
    if (XQC_UNLIKELY(xqc_conn_has_undecrypt_packets(conn))) {   \
        xqc_conn_process_undecrypt_packets(conn);               \
        XQC_CHECK_IMMEDIATE_CLOSE();                            \
    }                                                           \
} while(0);                                                     \

#define XQC_CHECK_IMMEDIATE_CLOSE() do {                        \
    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_IMMEDIATE_CLOSE_FLAGS)) {     \
        xqc_conn_immediate_close(conn);                         \
        goto end;                                               \
    }                                                           \
} while(0);                                                     \

void
xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|state:%s|flag:%s|now:%ui|",
            conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

    int ret;

    xqc_send_ctl_timer_expire(conn->conn_send_ctl, now);

    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_TIME_OUT)) {
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return;
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (XQC_UNLIKELY(conn->conn_state >= XQC_CONN_STATE_CLOSING)) {
        goto end;
    }

    XQC_CHECK_UNDECRYPT_PACKETS();
    xqc_process_crypto_read_streams(conn);
    XQC_CHECK_UNDECRYPT_PACKETS();
    xqc_process_crypto_write_streams(conn);
    XQC_CHECK_UNDECRYPT_PACKETS();
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (XQC_UNLIKELY(!xqc_list_empty(&conn->conn_send_ctl->ctl_buff_1rtt_packets) &&
        conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        xqc_conn_write_buffed_1rtt_packets(conn);
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        xqc_process_read_streams(conn);
        if (xqc_send_ctl_can_write(conn->conn_send_ctl)) {
            xqc_process_write_streams(conn);
        } else {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_can_write false|");
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (xqc_conn_should_ack(conn)) {
        ret = xqc_write_ack_to_packets(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_to_packets error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_PING)) {
        ret = xqc_write_ping_to_packet(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ping_to_packet error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

end:
    conn->packet_need_process_count = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_NEED_RUN;
    return;
}

void
xqc_engine_recv_batch(xqc_engine_t *engine, xqc_connection_t * conn)
{
    xqc_engine_main_logic_internal(engine, conn);
}

void xqc_engine_finish_recv (xqc_engine_t *engine){
    xqc_engine_main_logic(engine);
}

void xqc_engine_main_logic_internal(xqc_engine_t *engine, xqc_connection_t * conn){
    if(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY){
        return;
    }
    conn->conn_flag |= XQC_CONN_FLAG_CANNOT_DESTROY;
    xqc_engine_main_logic(engine);
    conn->conn_flag &= ~XQC_CONN_FLAG_CANNOT_DESTROY;
}

/**
 * Process all connections
 */
void
xqc_engine_main_logic (xqc_engine_t *engine)
{
    if (engine->engine_flag & XQC_ENG_FLAG_RUNNING) {
        xqc_log(engine->log, XQC_LOG_DEBUG, "|engine is running|");
        return;
    }
    engine->engine_flag |= XQC_ENG_FLAG_RUNNING;

    xqc_log(engine->log, XQC_LOG_DEBUG, "|");

    xqc_msec_t now = xqc_now();
    xqc_connection_t *conn;

    while (!xqc_wakeup_pq_empty(engine->conns_wait_wakeup_pq)) {
        xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq); //
        if (XQC_UNLIKELY(el == NULL || el->conn == NULL)) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq); //pop操作与top操作中不能有push动作
            continue;
        }
        conn = el->conn;

        //xqc_log(conn->log, XQC_LOG_DEBUG, "|wakeup|conn:%p|state:%s|flag:%s|now:%ui|wakeup:%ui|",
        //        conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now, el->wakeup_time);
        if (el->wakeup_time <= now) {
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);//pop操作需要尽量靠近top操作，中间不能有push动作
            conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;

            if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
                if (0 == xqc_conns_pq_push(engine->conns_active_pq, conn, conn->last_ticked_time)) {
                    conn->conn_flag |= XQC_CONN_FLAG_TICKING;
                } else {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|");
                }
            }
        } else {
            break;
        }
    }

    while (!xqc_pq_empty(engine->conns_active_pq)) {
        conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
        if (XQC_UNLIKELY(conn == NULL)) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
            continue;
        }

        xqc_log(conn->log, XQC_LOG_DEBUG, "|ticking|conn:%p|state:%s|flag:%s|now:%ui|",
                conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

        now = xqc_now();
        xqc_engine_process_conn(conn, now);

        if (XQC_UNLIKELY(conn->conn_state == XQC_CONN_STATE_CLOSED)) {
            conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
            //xqc_conn_destroy(conn);
            if(!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)){
                xqc_conn_destroy(conn);
            }else{
                if (!(conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }
            }
            continue;
        } else {
            conn->last_ticked_time = now;

            xqc_conn_retransmit_lost_packets(conn);
            xqc_conn_send_packets(conn);

            if (XQC_UNLIKELY(conn->conn_state == XQC_CONN_STATE_CLOSED)) {
                conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
                //xqc_conn_destroy(conn);
                if(!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)){
                    xqc_conn_destroy(conn);
                }else{
                    if (!(conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                        xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                        conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                    }
                }
                continue;
            }
            conn->next_tick_time = xqc_conn_next_wakeup_time(conn);
            if (conn->next_tick_time) {
                if (!(conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, conn->next_tick_time, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }
                else {
                    //remove from pq then push again, update wakeup time
                    xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, conn->next_tick_time, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }
            } else {
                /* 至少会有idle定时器，这是异常分支 */
                xqc_log(conn->log, XQC_LOG_ERROR, "|destroy_connection|");
                conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
                //xqc_conn_destroy(conn);
                if(!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)){
                    xqc_conn_destroy(conn);
                }else{

                    if (!(conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                        xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                        conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                    }
                }
                continue;
            }
        }

        /* xqc_engine_process_conn有可能会插入conns_active_pq，XQC_CONN_FLAG_TICKING防止重复插入，
         * 必须放在xqc_engine_process_conn后 */
        conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    }

    xqc_msec_t wake_after = xqc_engine_wakeup_after(engine);
    if (wake_after > 0) {

        engine->eng_callback.set_event_timer(engine->user_data, wake_after);
    }

    engine->engine_flag &= ~XQC_ENG_FLAG_RUNNING;
    return;
}

/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet recieved time in microsecond
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
    if (XQC_UNLIKELY(xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len, (unsigned char *)packet_in_buf, packet_in_size) != XQC_OK)) {
        xqc_log(engine->log, XQC_LOG_WARN, "|fail to parse cid|");
        return -XQC_EILLPKT;
    }
    //xqc_log(engine->log, XQC_LOG_DEBUG, "|scid:%s|dcid:%s|", xqc_scid_str(&scid), xqc_dcid_str(&dcid));

    conn = xqc_engine_conns_hash_find(engine, &scid, 's');

    /* server creates connection when receiving a initial packet*/
    if (XQC_UNLIKELY(conn == NULL
            && engine->eng_type == XQC_ENGINE_SERVER
            && XQC_PACKET_IS_LONG_HEADER(packet_in_buf)
            &&
                (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_INIT
                || XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_0RTT)
            && (local_addr != NULL && peer_addr != NULL) //防止server新建连接时源目的地址为空
            )) {

        /* 防止initial包重传重复创建连接 */
        conn = xqc_engine_conns_hash_find(engine, &dcid, 'd');
        if (conn) {
            goto process;
        }

        conn = xqc_conn_server_create(engine,
                                      local_addr, local_addrlen,
                                      peer_addr, peer_addrlen,
                                      &dcid, &scid,
                                      &(engine->eng_callback.conn_callbacks),
                                      &default_conn_settings,
                                      user_data);
        if (conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
            return -XQC_ECREATE_CONN;
        }
    }
    if (XQC_UNLIKELY(conn == NULL)) {
        if (!xqc_is_reset_packet(&scid, packet_in_buf, packet_in_size)) {
            if (xqc_engine_schedule_reset(engine, peer_addr, peer_addrlen, recv_time) != XQC_OK) {
                return -XQC_ECONN_NFOUND;
            }
            xqc_log(engine->log, XQC_LOG_WARN, "|fail to find connection, send reset|size:%uz|scid:%s|",
                    packet_in_size, xqc_scid_str(&scid));
            ret = xqc_conn_send_reset(engine, &scid, user_data, peer_addr, peer_addrlen);
            if (ret) {
                xqc_log(engine->log, XQC_LOG_ERROR, "|fail to send reset|");
            }
        } else {
            //RST包只有对端cid
            conn = xqc_engine_conns_hash_find(engine, &scid, 'd');
            if (conn) {
                xqc_log(engine->log, XQC_LOG_WARN, "|====>|receive reset, enter draining|size:%uz|scid:%s|",
                        packet_in_size, xqc_scid_str(&scid));
                if (conn->conn_state < XQC_CONN_STATE_DRAINING) {
                    conn->conn_state = XQC_CONN_STATE_DRAINING;
                    xqc_send_ctl_drop_packets(conn->conn_send_ctl);
                    xqc_msec_t pto = xqc_send_ctl_calc_pto(conn->conn_send_ctl);
                    if (!xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_DRAINING)) {
                        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_DRAINING, 3 * pto + recv_time);
                    }
                }
                goto after_process;
            }
            xqc_log(engine->log, XQC_LOG_WARN, "|fail to find connection, exit|size:%uz|scid:%s|",
                    packet_in_size, xqc_scid_str(&scid));
        }
        return -XQC_ECONN_NFOUND;
    }

process:
    xqc_log(engine->log, XQC_LOG_INFO, "|==>|conn:%p|size:%uz|state:%s|recv_time:%ui|",
            conn, packet_in_size, xqc_conn_state_2_str(conn->conn_state), recv_time);

    if (XQC_UNLIKELY(conn->local_addrlen == 0)) {
        xqc_memcpy(conn->local_addr, local_addr, local_addrlen);
        conn->local_addrlen = local_addrlen;
    }

    /* process packets */
    ret = xqc_packet_process(conn, packet_in_buf, packet_in_size, recv_time);
    if (ret) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to process packets|conn:%p|ret:%d|", conn, ret);
        XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
        goto after_process;
    }

    conn->conn_send_ctl->ctl_bytes_recv += packet_in_size;
    conn->conn_send_ctl->ctl_recv_count++;

    xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_IDLE,
                           recv_time + conn->conn_send_ctl->ctl_conn->local_settings.idle_timeout*1000);


after_process:
    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        } else {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|conn:%p|", conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            xqc_conn_destroy(conn);
            return -XQC_EFATAL;
        }
    }

    /* main logic */
    if (++conn->packet_need_process_count >= XQC_MAX_PACKET_PROCESS_BATCH ||
        conn->conn_err != 0 ||
        conn->conn_flag & XQC_CONN_FLAG_NEED_RUN) {
        xqc_engine_main_logic_internal(engine, conn);
        if(xqc_engine_conns_hash_find(engine, &scid, 's') == NULL){ //用于当连接在main logic中destroy时，需要返回错误让上层感知
            return  -XQC_ECONN_NFOUND;
        }
    }

    return ret;
}


uint8_t
xqc_engine_config_get_cid_len(xqc_engine_t *engine)
{
    return engine->config->cid_len;
}
