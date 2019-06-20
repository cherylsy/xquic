
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_conn.h"
#include "../transport/xqc_client.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_str.h"
#include "../congestion_control/xqc_new_reno.h"

int xqc_test_client_conn_notify(xqc_cid_t *cid, void *user_data)
{
    //printf("%s\n",__FUNCTION__);
    return 0;
}

void xqc_test_conn_create()
{
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT);

    xqc_engine_callback_t callback = {
        .conn_callbacks = {
            .conn_create_notify = xqc_test_client_conn_notify,
        },
        .cong_ctrl_callback = xqc_reno_cb,
    };
    xqc_engine_set_callback(engine, callback);

    CU_ASSERT(engine != NULL);

    xqc_cid_t *cid = xqc_connect(engine, NULL);
    CU_ASSERT_NOT_EQUAL(cid, NULL);

    xqc_engine_destroy(engine);
}

