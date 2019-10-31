
#include <CUnit/CUnit.h>
#include "include/xquic.h"
#include "transport/xqc_conn.h"
#include "transport/xqc_client.h"
#include "include/xquic_typedef.h"
#include "common/xqc_str.h"
#include "congestion_control/xqc_new_reno.h"
#include "xqc_common_test.h"
#include "transport/xqc_engine.h"

void xqc_test_conn_create()
{
    def_engine_ssl_config;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config);

    xqc_engine_callback_t callback = {
    };
    xqc_engine_set_callback(engine, callback);

    CU_ASSERT(engine != NULL);

    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_cid_t *cid = xqc_connect(engine, NULL, NULL, 0, "", 0, &conn_ssl_config);
    CU_ASSERT_NOT_EQUAL(cid, NULL);

    xqc_engine_destroy(engine);
}

