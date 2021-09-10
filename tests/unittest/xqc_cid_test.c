#include <CUnit/CUnit.h>
#include "xqc_cid_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"

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

    ret = xqc_cid_set_insert_cid(&conn->scid_set.cid_set, &test_scid, XQC_CID_UNUSED, conn->remote_settings.active_connection_id_limit);
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

    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &test_dcid, XQC_CID_UNUSED, conn->local_settings.active_connection_id_limit);
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

void xqc_test_new_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid;

    /* New Conn ID */
    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->scid_set.cid_set.unused_cnt == 1);

    ret = xqc_get_unused_cid(&conn->scid_set.cid_set, &test_scid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->scid_set.cid_set.unused_cnt == 0);
}

void xqc_test_retire_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_dcid;

    /* Retire Conn ID */
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == -XQC_ECONN_NO_AVAIL_CID);

    ret = xqc_generate_cid(conn->engine, NULL, &test_dcid, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &test_dcid, XQC_CID_UNUSED, conn->local_settings.active_connection_id_limit);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
}

void
xqc_test_recv_retire_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid, test_dcid;

    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_get_unused_cid(&conn->scid_set.cid_set, &test_scid);
    CU_ASSERT(ret == XQC_OK);

    xqc_cid_t ori_cid;
    xqc_cid_copy(&ori_cid, &conn->scid_set.user_scid);

    /* Recv Retire_CID Frame */
    char XQC_RETIRE_CID_FRAME[] = {0x19,       /* type */ 
                                   0x00,       /* Sequence Number */};
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(xqc_packet_in_t));
    packet_in.pos = XQC_RETIRE_CID_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_RETIRE_CID_FRAME);

    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pi_frame_types == XQC_FRAME_BIT_RETIRE_CONNECTION_ID);

    // ori_scid retired
    xqc_cid_inner_t *ori_inner_cid = xqc_cid_in_cid_set(&conn->scid_set.cid_set, &ori_cid);
    CU_ASSERT(ori_inner_cid != NULL);
    CU_ASSERT(ori_inner_cid->state == XQC_CID_RETIRED);

    // user_scid updated
    CU_ASSERT(xqc_cid_is_equal(&conn->scid_set.user_scid, &test_scid) == XQC_OK);

    // retired timer
    CU_ASSERT(xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_RETIRE_CID));
}

void xqc_test_cid()
{
    xqc_test_cid_basic();
    xqc_test_new_cid();
    xqc_test_retire_cid();
    xqc_test_recv_retire_cid();
}