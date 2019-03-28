#ifndef _XQC_H_CONFIG_INCLUDED_
#define _XQC_H_CONFIG_INCLUDED_

#define xqc_min(a, b) ((a) < (b) ? (a) : (b))
#define xqc_max(a, b) ((a) > (b) ? (a) : (b))

#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"

#define XQC_PTR_SIZE 8

#define XQC_INT32_LEN   (sizeof("-2147483648") - 1)
#define XQC_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (XQC_PTR_SIZE == 4)
# define XQC_INT_T_LEN XQC_INT32_LEN
# define XQC_MAX_INT_T_VALUE  2147483647

#else
# define XQC_INT_T_LEN XQC_INT64_LEN
# define XQC_MAX_INT_T_VALUE  9223372036854775807
#endif

#define XQC_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define XQC_MAX_INT32_VALUE   (uint32_t) 0x7fffffff

#endif /*_XQC_H_CONFIG_INCLUDED_*/
