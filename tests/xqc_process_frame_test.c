#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/common/xqc_variable_len_int.h"

char XQC_TEST_ILL_FRAME_1[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME[] = {0x07, 0x00};
char XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME[] = {0x16, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
void xqc_test_process_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t packet_in;
    packet_in.pos = XQC_TEST_ILL_FRAME_1;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ILL_FRAME_1);
    int ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EILLPKT);

    packet_in.pos = XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    packet_in.pos = XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPARAM);
}