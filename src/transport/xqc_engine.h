
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <openssl/ssl.h>

typedef enum {
    XQC_ENG_FLAG_RUNNING    = 1 << 0,
} xqc_engine_flag_t;

typedef struct xqc_ssl_session_ticket_key_s{
    size_t                      size;
    uint8_t                     name[16];
    uint8_t                     hmac_key[32];
    uint8_t                     aes_key[32];
} xqc_ssl_session_ticket_key_t;

typedef struct xqc_engine_s {
    xqc_engine_type_t       eng_type;

    xqc_engine_callback_t   eng_callback;
    xqc_config_t           *config;
    xqc_str_hash_table_t   *conns_hash; /*scid*/
    xqc_str_hash_table_t   *conns_hash_dcid; /*For reset packet*/
    xqc_pq_t               *conns_active_pq; /* In process */
    xqc_wakeup_pq_t        *conns_wait_wakeup_pq; /* Need wakeup after next tick time */

    xqc_log_t              *log;
    xqc_random_generator_t *rand_generator;

    void                   *user_data;

    SSL_CTX                *ssl_ctx;  //for ssl
    BIO_METHOD             *ssl_meth; //for ssl bio method
    xqc_engine_ssl_config_t       ssl_config; //ssl config, such as cipher suit, cert file path etc.
    xqc_ssl_session_ticket_key_t  session_ticket_key;

    xqc_h3_context_t       *h3_ctx;

    xqc_engine_flag_t       engine_flag;
#define XQC_RESET_CNT_ARRAY_LEN 16384
    uint8_t                 reset_sent_cnt[XQC_RESET_CNT_ARRAY_LEN]; /* remote addr hash */
    xqc_msec_t              reset_sent_cnt_cleared;
}xqc_engine_t;

xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

void xqc_engine_set_callback(xqc_engine_t *engine,
                             const xqc_engine_callback_t *engine_callback);

/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);

void xqc_engine_config_destroy(xqc_config_t *config);


/**
 * @return >0 : user should call xqc_engine_main_logic after N ms
 */
xqc_msec_t xqc_engine_wakeup_after (xqc_engine_t *engine);

xqc_connection_t * xqc_engine_conns_hash_find(xqc_engine_t *engine, const xqc_cid_t *cid, char type);

void xqc_engine_process_conn (xqc_connection_t *conn, xqc_msec_t now);

void xqc_engine_main_logic_internal(xqc_engine_t *engine, xqc_connection_t * conn);

#endif

