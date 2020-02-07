#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "transport/xqc_frame.h"
#include "transport/xqc_packet_in.h"

#define ILL_FRAME_1 "/xff/x00/x00/x00"
void xqc_test_process_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t packet_in;
    packet_in.pos = ILL_FRAME_1;
    packet_in.last = ILL_FRAME_1 + sizeof(ILL_FRAME_1) - 1;
    int ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EILLPKT);
}