
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

void xqc_test_short_header_packet_parse_cid()
{
    unsigned char dcid_buf[XQC_MAX_CID_LEN * 2];
    unsigned char scid_buf[XQC_MAX_CID_LEN * 2];

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);

    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, 
                        (unsigned char *)XQC_TEST_SHORT_HEADER_PACKET_A,
                        sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1);
    CU_ASSERT(rc == XQC_OK);

    xqc_hex_dump(dcid_buf, dcid.cid_buf, dcid.cid_len);
    xqc_hex_dump(scid_buf, scid.cid_buf, scid.cid_len);

    xqc_log(engine->log, XQC_LOG_WARN, "parse cid|%z|%*s|%z|%*s|",
                                       dcid.cid_len, dcid.cid_len*2, dcid_buf,
                                       scid.cid_len, scid.cid_len*2, scid_buf);

    xqc_engine_destroy(engine);
}

