#include <CUnit/CUnit.h>
#include "xqc_cid_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"

#define XQC_TEST_CID_1 "xquictestconnid1"
#define XQC_TEST_CID_2 "xquictestconnid2"

void xqc_test_cid_basic()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid, test_dcid;

    ret = xqc_generate_cid(conn->engine, NULL, &test_scid, 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_insert_cid(&conn->scid_set.cid_set, &test_scid, XQC_CID_UNUSED);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set.cid_set, &test_scid) != NULL);
    CU_ASSERT(xqc_cid_is_equal(xqc_get_cid_by_seq(&conn->scid_set.cid_set, 1), &test_scid) == XQC_OK)

    ret = xqc_get_unused_cid(&conn->scid_set.cid_set, &test_scid);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_delete_cid(&conn->scid_set.cid_set, &test_scid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set.cid_set, &test_scid) == NULL);
    CU_ASSERT(xqc_cid_is_equal(xqc_get_cid_by_seq(&conn->scid_set.cid_set, 1), &test_scid) != XQC_OK)


    ret = xqc_generate_cid(conn->engine, NULL, &test_dcid, 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &test_dcid, XQC_CID_UNUSED);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->dcid_set.cid_set, &test_dcid) != NULL);
    CU_ASSERT(xqc_cid_is_equal(xqc_get_cid_by_seq(&conn->dcid_set.cid_set, 1), &test_dcid) == XQC_OK)

    ret = xqc_get_unused_cid(&conn->dcid_set.cid_set, &test_dcid);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_delete_cid(&conn->dcid_set.cid_set, &test_dcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->dcid_set.cid_set, &test_dcid) == NULL);
    CU_ASSERT(xqc_cid_is_equal(xqc_get_cid_by_seq(&conn->dcid_set.cid_set, 1), &test_dcid) != XQC_OK)

}

void xqc_test_cid_new_and_retire()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid, test_dcid;

    /* New Conn ID */
    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->scid_set.cid_set.unused_cnt == 1);

    ret = xqc_get_unused_cid(&conn->scid_set.cid_set, &test_scid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->scid_set.cid_set.unused_cnt == 0);

    ret = xqc_conn_update_user_scid(conn, &conn->scid_set);
    CU_ASSERT(xqc_cid_is_equal(&conn->scid_set.user_scid, &test_scid) == XQC_OK);

    /* Retire Conn ID */
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == -XQC_ECONN_NO_AVAIL_CID);

    ret = xqc_generate_cid(conn->engine, NULL, &test_dcid, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &test_dcid, XQC_CID_UNUSED);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);

}

void xqc_test_cid()
{
    xqc_test_cid_basic();

    xqc_test_cid_new_and_retire();

}