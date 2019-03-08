
#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * @file
 * Public API for using libxquic
 */

typedef struct xqc_engine xqc_engine_t;

/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {

}xqc_config_t;

typedef enum {
    XQC_ENGINE_SERVER,
    XQC_ENGINE_CLIENT
}xqc_engine_type_t;

typedef struct xqc_engine_api {

}xqc_engine_api_t;


/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *xqc_engine_new (xqc_engine_type_t engine_type);

/**
 * Init engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
void xqc_engine_init_config (xqc_engine_t *engine,
                             xqc_config_t *engine_config, 
                             xqc_engine_type_t engine_type);

/**
 * Set xquic engine API.
 */
void xqc_engine_set_api (xqc_engine_t *engine,
                         xqc_engine_api_t *engine_api);


xqc_conn_t *xqc_engine_connect (xqc_engine_t *engine, 
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen);




#endif /* _XQUIC_H_INCLUDED_ */

