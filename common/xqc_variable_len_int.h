
#ifndef _XQC_VARIABLE_LEN_INT_H_INCLUDED_
#define _XQC_VARIABLE_LEN_INT_H_INCLUDED_

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#include <sys/endian.h>
#define bswap_16 bswap16
#define bswap_32 bswap32
#define bswap_64 bswap64
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#elif defined(WIN32)
#include <stdlib.h>
#define bswap_16 _byteswap_ushort
#define bswap_32 _byteswap_ulong
#define bswap_64 _byteswap_uint64
#else
#include <byteswap.h>
#endif

#define VINT_MASK ((1 << 6) - 1)

/*
          +------+--------+-------------+-----------------------+
          | 2Bit | Length | Usable Bits | Range                 |
          +------+--------+-------------+-----------------------+
          | 00   | 1      | 6           | 0-63                  |
          |      |        |             |                       |
          | 01   | 2      | 14          | 0-16383               |
          |      |        |             |                       |
          | 10   | 4      | 30          | 0-1073741823          |
          |      |        |             |                       |
          | 11   | 8      | 62          | 0-4611686018427387903 |
          +------+--------+-------------+-----------------------+
 */

/* return 2Bit 00, 01, 10 or 11 (0, 1, 2, or 3) */
#define vint_get_2bit(val) (    \
    (val >= (1 << 6)) + (val >= (1 << 14)) + (val >= (1 << 30)))

/* return Usable Bits according to 2Bit.
 * parameter _2bit can be 0, 1, 2, 3
 */
#define vint_usable_bits(_2bit) ((1 << (3 + (bits))) - 2)

/* get Length by 2Bit */
#define vint_len(_2bit) (1<<_2bit)

/* write val to dst buf with len bytes  */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define vint_write(dst, val, _2bits, len) do {                              \
    uint64_t buf_ = (val) | (uint64_t) (_2bits) << vint_usable_bits(_2bits);\
    buf_ = bswap_64(buf_);                                                  \
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#else
#define vint_write(dst, val, _2bits, len) do {                                \
    uint64_t buf_ = (val) | (uint64_t) (_2bits) << vint_usable_bits(_2bits);\
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#endif

int xqc_vint_read (const unsigned char *p, const unsigned char *end, uint64_t *valp);

#endif /* _XQC_VARIABLE_LEN_INT_H_INCLUDED_ */
