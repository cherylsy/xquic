
#include <CUnit/CUnit.h>

#include "xqc_packet_test.h"
#include "../transport/xqc_packet.h"
#include "../common/xqc_log.h"
#include "../transport/xqc_engine.h"
#include "../transport/xqc_cid.h"
#include "../include/xquic_typedef.h"
#include "../include/xquic.h"
#include "../common/xqc_str.h"


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\x00\x00\x00\x01\x55\xAB\x3f\x12\x0a\xcd\xef\x00\x89\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"

void xqc_test_packet_parse_cid(unsigned char *buf, size_t size)
{
    unsigned char dcid_buf[XQC_MAX_CID_LEN * 2];
    unsigned char scid_buf[XQC_MAX_CID_LEN * 2];

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);

    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, buf, size);
    CU_ASSERT(rc == XQC_OK);

    xqc_log(engine->log, XQC_LOG_WARN, "parse cid length|%z|%z|", dcid.cid_len, scid.cid_len);

    xqc_hex_dump(dcid_buf, dcid.cid_buf, dcid.cid_len);
    xqc_hex_dump(scid_buf, scid.cid_buf, scid.cid_len);

    xqc_log(engine->log, XQC_LOG_WARN, "parse cid|%*s|%*s|",
                                       ((size_t)dcid.cid_len * 2), dcid_buf,
                                       ((size_t)scid.cid_len * 2), scid_buf);

    CU_ASSERT(((size_t)dcid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));
    CU_ASSERT(((size_t)scid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));

    CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, dcid_buf, ((size_t)dcid.cid_len * 2)) == 0);
    CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, scid_buf, ((size_t)scid.cid_len * 2)) == 0);

    xqc_engine_destroy(engine);
}

void xqc_test_short_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_SHORT_HEADER_PACKET_A,
                        sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1);
}

void xqc_test_long_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_LONG_HEADER_PACKET_B,
                        sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1);
}


