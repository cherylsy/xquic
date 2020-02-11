
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
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_cid_t *cid = test_cid_connect(engine);
    CU_ASSERT_NOT_EQUAL(cid, NULL);

    xqc_engine_destroy(engine);
}

