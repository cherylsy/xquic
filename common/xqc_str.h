#ifndef _XQC_STR_H_INCLUDED_
#define _XQC_STR_H_INCLUDED_

typedef struct xqc_str_s
{
    unsigned char* data;
    size_t len;
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


#endif /*_XQC_STR_H_INCLUDED_*/
