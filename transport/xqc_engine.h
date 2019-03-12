
#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_

#include "xqc_transport.h"
#include "../include/xquic.h"

struct xqc_engine_s {
    xqc_engine_callback_t   eng_callback;
    xqc_config_t            *config;
    xqc_id_hash_table_t     *conns_hash;

    xqc_conn_settings_t     *settings;
};

#endif

