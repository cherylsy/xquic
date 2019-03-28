#ifndef _XQC_STR_H_INCLUDED_
#define _XQC_STR_H_INCLUDED_

#include <stdint.h>
#include <stdarg.h>
#include <time.h>

#include "xqc_config.h"

typedef struct xqc_str_s
{
    size_t len;
    unsigned char* data;
} xqc_str_t;

#define xqc_string(str)     { sizeof(str) - 1, (unsigned char *) str }
#define xqc_null_string     { 0, NULL }
#define xqc_str_set(str, text) (str)->len = sizeof(text) - 1; (str)->data = (unsigned char *) text
#define xqc_str_null(str)   (str)->len = 0; (str)->data = NULL

#define xqc_str_equal(s1, s2)  ((s1).len == (s2).len && memcmp((s1).data, (s2).data, (s1).len) == 0)

#define xqc_memzero(buf, n)       (void) memset(buf, 0, n)
#define xqc_memset(buf, c, n)     (void) memset(buf, c, n)

#define xqc_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define xqc_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))


static inline u_char *
xqc_sprintf_num(u_char *buf, u_char *last, uint64_t ui64, u_char zero, uintptr_t hexadecimal, uintptr_t width)
{
    u_char         *p, temp[XQC_INT64_LEN + 1];
                       /*
                        * we need temp[NGX_INT64_LEN] only,
                        * but icc issues the warning
                        */
    size_t          len;
    uint32_t        ui32;
    static u_char   hex[] = "0123456789abcdef";
    static u_char   HEX[] = "0123456789ABCDEF";

    p = temp + XQC_INT64_LEN;

    if (hexadecimal == 0) {
        if (ui64 <= (uint64_t) XQC_MAX_UINT32_VALUE) {
            ui32 = (uint32_t) ui64;

            do {
                *--p = (u_char) (ui32 % 10 + '0');
            } while (ui32 /= 10);
        } else {
            do {
                *--p = (u_char) (ui64 % 10 + '0');
            } while (ui64 /= 10);
        }

    } else if (hexadecimal == 1) {
        do {
            *--p = hex[(uint32_t) (ui64 & 0xf)];
        } while (ui64 >>= 4);

    } else { /* hexadecimal == 2 */

        do {
            *--p = HEX[(uint32_t) (ui64 & 0xf)];

        } while (ui64 >>= 4);
    }

    /* zero or space padding */

    len = (temp + XQC_INT64_LEN) - p;

    while (len++ < width && buf < last) {
        *buf++ = zero;
    }

    /* number safe copy */

    len = (temp + XQC_INT64_LEN) - p;

    if (buf + len > last) {
        len = last - buf;
    }

    return xqc_cpymem(buf, p, len);
}

static inline unsigned char* 
xqc_vsprintf(unsigned char* buf, unsigned char* last, const char* fmt, va_list args)
{
    u_char *p, zero;
    int d;
    double f;
    size_t len, slen;
    int64_t i64;
    uint64_t ui64, frac;
    uint64_t width, sign, hex, max_width, frac_width, scale, n;
    xqc_str_t *v;

    while (*fmt && buf < last) {

        if (*fmt == '%') {
            i64 = 0;
            ui64 = 0;

            zero = (u_char) ((*++fmt == '0') ? '0' : ' ');
            width = 0;
            sign = 1;
            hex = 0;
            max_width = 0;
            frac_width = 0;
            slen = (size_t) -1;

            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + *fmt++ - '0';
            }

            for ( ;; ) {
                switch (*fmt) {
                case 'u':
                    sign = 0;
                    fmt++;
                    continue;

                case 'm':
                    max_width = 1;
                    fmt++;
                    continue;

                case 'X':
                    hex = 2;
                    sign = 0;
                    fmt++;
                    continue;

                case 'x':
                    hex = 1;
                    sign = 0;
                    fmt++;
                    continue;

                case '.':
                    fmt++;
                    while (*fmt >= '0' && *fmt <= '9') {
                        frac_width = frac_width * 10 + *fmt++ - '0';
                    }
                    break;

                case '*':
                    slen = va_arg(args, size_t);
                    fmt++;
                    continue;

                default:
                    break;
                }

                break;
            }


            switch (*fmt) {

            case 'V':
                v = va_arg(args, xqc_str_t *);
                len = xqc_min(((size_t) (last - buf)), v->len);
                buf = xqc_cpymem(buf, v->data, len);
                fmt++;
                continue;

            case 's':
                p = va_arg(args, u_char *);
                if (slen == (size_t) -1) {
                    while (*p && buf < last) {
                        *buf++ = *p++;
                    }
                } else {
                    len = xqc_min(((size_t) (last - buf)), slen);
                    buf = xqc_cpymem(buf, p, len);
                }
                fmt++;
                continue;

            case 'O':
                i64 = (int64_t) va_arg(args, off_t);
                sign = 1;
                break;

            case 'P':
                i64 = (int64_t) va_arg(args, int64_t);
                sign = 1;
                break;

            case 'T':
                i64 = (int64_t) va_arg(args, time_t);
                sign = 1;
                break;

            case 'z':
                if (sign) {
                    i64 = (int64_t) va_arg(args, ssize_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, size_t);
                }
                break;

            case 'i':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int64_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, uint64_t);
                }

                if (max_width) {
                    width = XQC_INT_T_LEN;
                }
                break;

            case 'd':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int);
                } else {
                    ui64 = (uint64_t) va_arg(args, unsigned int);
                }
                break;

            case 'l':
                if (sign) {
                    i64 = (int64_t) va_arg(args, long);
                } else {
                    ui64 = (uint64_t) va_arg(args, unsigned long);
                }
                break;

            case 'D':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int32_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, uint32_t);
                }
                break;

            case 'L':
                if (sign) {
                    i64 = va_arg(args, int64_t);
                } else {
                    ui64 = va_arg(args, uint64_t);
                }
                break;

            case 'f':
                f = va_arg(args, double);

                if (f < 0) {
                    *buf++ = '-';
                    f = -f;
                }

                ui64 = (int64_t) f;
                frac = 0;

                if (frac_width) {
                    scale = 1;
                    for (n = frac_width; n; n--) {
                        scale *= 10;
                    }

                    frac = (uint64_t) ((f - (double) ui64) * scale + 0.5);

                    if (frac == scale) {
                        ui64++;
                        frac = 0;
                    }
                }

                buf = xqc_sprintf_num(buf, last, ui64, zero, 0, width);

                if (frac_width) {
                    if (buf < last) {
                        *buf++ = '.';
                    }
                    buf = xqc_sprintf_num(buf, last, frac, '0', 0, frac_width);
                }

                fmt++;

                continue;

            case 'r':
                i64 = (int64_t) va_arg(args, rlim_t);
                sign = 1;
                break;

            case 'p':
                ui64 = (uintptr_t) va_arg(args, void *);
                hex = 2;
                sign = 0;
                zero = '0';
                width = XQC_PTR_SIZE * 2;
                break;

            case 'c':
                d = va_arg(args, int);
                *buf++ = (u_char) (d & 0xff);
                fmt++;
                continue;

            case 'Z':
                *buf++ = '\0';
                fmt++;
                continue;

            case 'N':
                *buf++ = LF;
                fmt++;
                continue;

            case '%':
                *buf++ = '%';
                fmt++;
                continue;

            default:
                *buf++ = *fmt++;
                continue;
            }

            if (sign) {
                if (i64 < 0) {
                    *buf++ = '-';
                    ui64 = (uint64_t) -i64;

                } else {
                    ui64 = (uint64_t) i64;
                }
            }
            buf = xqc_sprintf_num(buf, last, ui64, zero, hex, width);
            fmt++;

        } else {
            *buf++ = *fmt++;
        }
    }

    return buf;
}

static inline unsigned char* 
xqc_sprintf(unsigned char* buf, unsigned char* last, const char* fmt, ...)
{
    unsigned char *p;
    va_list args;

    va_start(args, fmt);
    p = xqc_vsprintf(buf, last, fmt, args);
    va_end(args);

    return p;
}

#endif /*_XQC_STR_H_INCLUDED_*/
