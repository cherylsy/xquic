
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_conn.h"

void xqc_test_conn_create()
{
    xqc_engine_t engine;
    xqc_client_connection_t client_conn;
    xqc_memzero(&client_conn, sizeof(xqc_client_connection_t));
    
    xqc_int_t rc = xqc_connect(&client_conn, &engine, NULL);
    CU_ASSERT(rc, XQC_OK);
    CU_ASSERT_NOT_EQUAL(client_conn.xc, NULL);

    xqc_destroy_connection(client_conn.xc);
}

