#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_random_test.h"
#include "xqc_timer_test.h"
#include "xqc_pq_test.h"
#include "xqc_conn_test.h"
#include "xqc_engine_test.h"
#include "xqc_common_test.h"
#include "xqc_vint_test.h"
#include "xqc_recv_record_test.h"
#include "xqc_reno_test.h"
#include "xqc_packet_test.h"

static int xqc_init_suite(void) { return 0; }
static int xqc_clean_suite(void) { return 0; }

int main()
{
    CU_pSuite pSuite = NULL;
    unsigned int failed_tests_count;

    if (CU_initialize_registry() != CUE_SUCCESS) {
        printf("CU_initialize error\n");
        return (int)CU_get_error();
    }

    pSuite = CU_add_suite("libxquic_TestSuite", xqc_init_suite, xqc_clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }     

    if (!CU_add_test(pSuite, "xqc_test_get_random", xqc_test_get_random)
        || !CU_add_test(pSuite, "xqc_test_engine_create", xqc_test_engine_create)
        || !CU_add_test(pSuite, "xqc_test_conn_create", xqc_test_conn_create)
        || !CU_add_test(pSuite, "xqc_test_timer", xqc_test_timer)
        || !CU_add_test(pSuite, "xqc_test_pq", xqc_test_pq)
        || !CU_add_test(pSuite, "xqc_test_common", xqc_test_common)
        || !CU_add_test(pSuite, "xqc_test_vint", xqc_test_vint)
        || !CU_add_test(pSuite, "xqc_test_recv_record", xqc_test_recv_record)
        || !CU_add_test(pSuite, "xqc_test_reno", xqc_test_reno)
        || !CU_add_test(pSuite, "xqc_test_short_header_parse_cid", xqc_test_short_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_long_header_parse_cid", xqc_test_long_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_engine_packet_process", xqc_test_engine_packet_process)
        /* ADD TESTS HERE */) 
    {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed_tests_count = CU_get_number_of_tests_failed();

    CU_cleanup_registry();
    if (CU_get_error() == CUE_SUCCESS) {
        return (int)failed_tests_count;
    } else {
        printf("CUnit Error: %s\n", CU_get_error_msg());
        return (int)CU_get_error();
    }

    CU_cleanup_registry();
    return (int)CU_get_error();
}
