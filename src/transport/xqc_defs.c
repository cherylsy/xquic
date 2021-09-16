#include "xqc_defs.h"
#include "xqc_str.h"
#include <string.h>

const uint32_t xqc_proto_version_value[XQC_VERSION_MAX] = {
    0xFFFFFFFF,
    0x00000001,
    0xFF00001D,
    0x00000000,
};


const unsigned char xqc_proto_version_field[XQC_VERSION_MAX][XQC_PROTO_VERSION_LEN] = {
    [XQC_IDRAFT_INIT_VER]        = { 0xFF, 0xFF, 0xFF, 0xFF, },  /* placeholder */
    [XQC_VERSION_V1]             = { 0x00, 0x00, 0x00, 0x01, },
    [XQC_IDRAFT_VER_29]          = { 0xFF, 0x00, 0x00, 0x1D, },
    [XQC_IDRAFT_VER_NEGOTIATION] = { 0x00, 0x00, 0x00, 0x00, },
};


const char* const xqc_crypto_initial_salt[] = {
    [XQC_IDRAFT_INIT_VER]        = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  /* placeholder */
    [XQC_VERSION_V1]             = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",  /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99",  /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};


xqc_bool_t
xqc_alpn_type_is_h3(const unsigned char *alpn, uint8_t alpn_len)
{
    return ((alpn_len == xqc_lengthof(XQC_ALPN_H3) && memcmp(alpn, XQC_ALPN_H3, xqc_lengthof(XQC_ALPN_H3)) == 0)
        || (alpn_len == xqc_lengthof(XQC_ALPN_H3_29) && memcmp(alpn, XQC_ALPN_H3_29, xqc_lengthof(XQC_ALPN_H3_29)) == 0));
}

xqc_bool_t
xqc_alpn_type_is_transport(const unsigned char *alpn, uint8_t alpn_len)
{
    return (alpn_len == xqc_lengthof(XQC_ALPN_TRANSPORT)
        && memcmp(alpn, XQC_ALPN_TRANSPORT, xqc_lengthof(XQC_ALPN_TRANSPORT)) == 0);
}


#define XQC_ALPN_HQ_INTEROP "hq-interop"
#define XQC_ALPN_HQ_29      "hq-29"

xqc_bool_t
xqc_alpn_type_is_hq(const unsigned char *alpn, uint8_t alpn_len)
{
    return ((alpn_len == xqc_lengthof(XQC_ALPN_HQ_INTEROP) && memcmp(alpn, XQC_ALPN_HQ_INTEROP, xqc_lengthof(XQC_ALPN_HQ_INTEROP)) == 0)
        || (alpn_len == xqc_lengthof(XQC_ALPN_HQ_29) && memcmp(alpn, XQC_ALPN_HQ_29, xqc_lengthof(XQC_ALPN_HQ_29)) == 0));
}

const char* const xqc_h3_alpn[] = {
    [XQC_IDRAFT_INIT_VER]        = "",     /* placeholder */
    [XQC_VERSION_V1]             = XQC_ALPN_H3,     /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = XQC_ALPN_H3_29,  /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "",
};

