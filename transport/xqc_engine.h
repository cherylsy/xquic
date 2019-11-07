
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include "include/xquic_typedef.h"
#include "include/xquic.h"

typedef enum {
    XQC_ENG_FLAG_RUNNING    = 1 << 0,
} xqc_engine_flag_t;

typedef struct xqc_engine_s {
    xqc_engine_type_t       eng_type;

    xqc_engine_callback_t   eng_callback;
    xqc_config_t           *config;
    xqc_str_hash_table_t   *conns_hash; /*scid*/
    xqc_str_hash_table_t   *conns_hash_dcid; /*For reset packet*/
    xqc_pq_t               *conns_active_pq; /* In process */
    xqc_wakeup_pq_t        *conns_wait_wakeup_pq; /* Need wakeup after next tick time */

    xqc_conn_settings_t    conn_settings;

    xqc_log_t              *log;
    xqc_random_generator_t *rand_generator;

    void                   *user_data;

    SSL_CTX                *ssl_ctx;  //for ssl
    xqc_engine_ssl_config_t       ssl_config; //ssl config, such as cipher suit, cert file path etc.
    xqc_ssl_session_ticket_key_t  session_ticket_key;

    xqc_engine_flag_t       engine_flag;
}xqc_engine_t;

xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);

void xqc_engine_config_destroy(xqc_config_t *config);

void xqc_engine_set_callback (xqc_engine_t *engine,
                         xqc_engine_callback_t engine_callback);

/**
 * @return >0 : user should call xqc_engine_main_logic after N ms
 */
xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

xqc_connection_t * xqc_engine_conns_hash_find(xqc_engine_t *engine, xqc_cid_t *cid, char type);

void xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now);


#endif

