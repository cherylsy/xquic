
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_conn.h"
#include "../transport/xqc_client.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_str.h"

int xqc_client_conn_notify(void *user_data, xqc_connection_t *conn)
{
    //printf("%s\n",__FUNCTION__);
    return 0;
}

void xqc_test_conn_create()
{
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT);

    xqc_engine_callback_t callback = {
        .conn_callbacks = {
            .conn_create_notify = xqc_client_conn_notify,
        }
    };
    xqc_engine_set_callback(engine, callback);

    CU_ASSERT(engine != NULL);

    xqc_connection_t *xc = xqc_connect(engine, NULL);
    CU_ASSERT_NOT_EQUAL(xc, NULL);

    xqc_destroy_connection(xc);
    xqc_engine_destroy(engine);
}

