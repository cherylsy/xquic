#ifndef _XQC_COMMON_H_INCLUDED_
#define _XQC_COMMON_H_INCLUDED_

#include <string.h>
#include <stdint.h>


#define XQC_OK 0
#define XQC_ERROR -1

#ifndef XQC_LITTLE_ENDIAN
# define XQC_LITTLE_ENDIAN 1
#endif

#ifndef XQC_NONALIGNED
# define XQC_NONALIGNED 1
#endif

typedef intptr_t        xqc_int_t;
typedef uintptr_t       xqc_uint_t;
typedef intptr_t        xqc_flag_t;

typedef unsigned char   u_char;

#endif /*_XQC_COMMON_H_INCLUDED_*/
