#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"

char XQC_TEST_ILL_FRAME_1[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME[] = {0x07, 0x00};
char XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME[] = {0x16, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};


void
xqc_test_process_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t packet_in;
    packet_in.pos = XQC_TEST_ILL_FRAME_1;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ILL_FRAME_1);
    int ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);

    packet_in.pos = XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    packet_in.pos = XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_OVERAGE_STREAM_BLOCKED_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPARAM);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_parse_padding_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    char XQC_PURE_PADDING_FRAME[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    xqc_packet_in_t pi_padding;
    memset(&pi_padding, 0, sizeof(xqc_packet_in_t));
    pi_padding.pos = XQC_PURE_PADDING_FRAME;
    pi_padding.last = pi_padding.pos + sizeof(XQC_PURE_PADDING_FRAME);
    int ret = xqc_process_frames(conn, &pi_padding);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(pi_padding.pi_frame_types == XQC_FRAME_BIT_PADDING);

    /* MAX_DATA frame after PADDING frame */
    char XQC_MIXED_PADDING_FRAME[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3F};
    xqc_packet_in_t pi_padding_mix;
    memset(&pi_padding_mix, 0, sizeof(xqc_packet_in_t));
    pi_padding_mix.pos = XQC_MIXED_PADDING_FRAME;
    pi_padding_mix.last = pi_padding_mix.pos + sizeof(XQC_MIXED_PADDING_FRAME);
    ret = xqc_process_frames(conn, &pi_padding_mix);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(pi_padding_mix.pi_frame_types == (XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_MAX_DATA));

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_large_ack_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    char XQC_ACK_FRAME[] = {0x02,       /* type */ 
                            0x40, 0xFF, /* Largest Acknowledged, 256 */
                            0x00,       /* ACK Delay */
                            0x40, 0x7F, /* ACK range count, 127 */
                            0x00,       /* first ack range */
                            0x00, 0x00, /* gap: 0, range: 0 */
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    xqc_packet_in_t pi_ack;
    memset(&pi_ack, 0, sizeof(xqc_packet_in_t));
    pi_ack.pos = XQC_ACK_FRAME;
    pi_ack.last = pi_ack.pos + sizeof(XQC_ACK_FRAME);

    int ret = xqc_process_frames(conn, &pi_ack);
    CU_ASSERT(pi_ack.pi_frame_types == XQC_FRAME_BIT_ACK);

    xqc_engine_destroy(conn->engine);
}

