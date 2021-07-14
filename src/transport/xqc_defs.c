#include "xqc_defs.h"
#include <xquic/xquic.h>

uint32_t xqc_proto_version_value[XQC_VERSION_MAX] = {
    0xFFFFFFFF,
    0x00000001,
    0xFF00001D,
    0xFF000021,
    0x00000000,
};


const unsigned char xqc_proto_version_field[XQC_VERSION_MAX][XQC_PROTO_VERSION_LEN] = {
    [XQC_IDRAFT_INIT_VER]        = { 0xFF, 0xFF, 0xFF, 0xFF, },  /* placeholder */
    [XQC_VERSION_V1]             = { 0x00, 0x00, 0x00, 0x01, },
    [XQC_IDRAFT_VER_29]          = { 0xFF, 0x00, 0x00, 0x1D, },
    [XQC_IDRAFT_VER_33]          = { 0xFF, 0x00, 0x00, 0x21, },
    [XQC_IDRAFT_VER_NEGOTIATION] = { 0x00, 0x00, 0x00, 0x00, },
};


const char* xqc_crypto_initial_salt[] = {
    [XQC_IDRAFT_INIT_VER]        = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  /* placeholder */
    [XQC_VERSION_V1]             = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",  /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99",  /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_33]          = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",  /* draft-33 ~ draft-34 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};