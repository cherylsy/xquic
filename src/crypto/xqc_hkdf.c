#include "src/crypto/xqc_hkdf.h"


int xqc_hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
        size_t secretlen, const uint8_t *label, size_t labellen,
        const xqc_digist_t *md) 
{

    unsigned char  info[256];
    static const uint8_t LABEL[] = "tls13 ";

    unsigned char * p = info;
    *p++ = destlen / 256;
    *p++ = destlen % 256;
    *p++ = strlen(LABEL) + labellen;
    p = xqc_cpymem(p, LABEL, strlen(LABEL));
    p = xqc_cpymem(p, label, labellen);
    *p++ = 0;
    return xqc_hkdf_expand(dest, destlen, secret, secretlen, info, p - info, md); // p-info 存疑,need finish
}
