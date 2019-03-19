
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_conn.h"
#include "../transport/xqc_client.h"
#include "../include/xquic_typedef.h"

void xqc_test_conn_create()
{
    xqc_engine_t engine;
    xqc_client_connection_t client_conn;
    xqc_config_t config;

    xqc_memzero(&client_conn, sizeof(xqc_client_connection_t));

    xqc_random_generator_init(&engine.rand_generator, engine.log);
    engine.config = &config;
    engine.config->conn_pool_size = 4096;
    engine.config->streams_hash_bucket_size = 127;
    
    xqc_int_t rc = xqc_connect(&client_conn, &engine, NULL);
    CU_ASSERT(rc == XQC_OK);
    CU_ASSERT_NOT_EQUAL(client_conn.xc, NULL);

    xqc_destroy_connection(client_conn.xc);
}

