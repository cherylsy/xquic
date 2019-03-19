
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_transport.h"


void xqc_test_engine_create()
{
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT);
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;

    engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;
}

