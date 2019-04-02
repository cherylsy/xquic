
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_transport.h"
#include "../transport/xqc_packet.h"
#include "../common/xqc_log.h"
#include "../transport/xqc_engine.h"
#include "../transport/xqc_cid.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_str.h"


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


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\x00\x00\x00\x01\x55\xAB\x3f\x12\x0a\xcd\xef\x00\x89\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"

void xqc_test_engine_packet_process()
{
    const struct sockaddr * local_addr = NULL;
    socklen_t local_addrlen = 0;
    const struct sockaddr * peer_addr = NULL;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);

    xqc_msec_t recv_time = xqc_gettimeofday();

    xqc_int_t rc = xqc_engine_packet_process(engine, 
                         XQC_TEST_LONG_HEADER_PACKET_B, sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1, 
                         local_addr, local_addrlen, 
                         peer_addr, peer_addrlen, recv_time);
    CU_ASSERT(rc == XQC_OK);

    recv_time = xqc_gettimeofday();
    rc = xqc_engine_packet_process(engine, 
                         XQC_TEST_SHORT_HEADER_PACKET_A, sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1, 
                         local_addr, local_addrlen, 
                         peer_addr, peer_addrlen, recv_time);
    CU_ASSERT(rc == XQC_OK);

    xqc_engine_destroy(engine);
}



