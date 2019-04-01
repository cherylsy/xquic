
#include <CUnit/CUnit.h>

#include "xqc_packet_test.h"
#include "../transport/xqc_packet.h"


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a"

void xqc_test_short_header_packet_parse_cid()
{
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);

    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, 
                        (unsigned char *)XQC_TEST_SHORT_HEADER_PACKET_A,
                        sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1);
    CU_ASSERT(rc == XQC_OK);

    xqc_log(engine->log, XQC_LOG_WARN, "parse cid|%zu|%xL|%zu|%xL|",
                                       dcid.cid_len, dcid.cid_buf,
                                       scid.cid_len, scid.cid_buf)

    xqc_engine_destroy(engine);
}

