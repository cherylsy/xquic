
#include "xqc_str.h"

unsigned char *
xqc_hex_dump(unsigned char *dst, unsigned char *src, size_t len)
{
    static unsigned char  hex[] = "0123456789abcdef";

    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xf];
    }

    return dst;
}


