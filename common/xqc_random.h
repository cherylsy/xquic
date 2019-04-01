
#ifndef _XQC_RANDOM_H_INCLUDED_
#define _XQC_RANDOM_H_INCLUDED_


#include <sys/types.h>

#include "xqc_str.h"
#include "xqc_log.h"
#include "xqc_common.h"
#include "../include/xquic_typedef.h"


typedef struct xqc_random_generator_s{
    /* for random */
    xqc_int_t               rand_fd;           /* init_value: -1 */
    off_t                   rand_buf_offset;   /* used offset */
    size_t                  rand_buf_size;     /* total buffer size */
    xqc_str_t               rand_buf;          /* buffer for random bytes*/

    xqc_log_t              *log;
}xqc_random_generator_t;

xqc_int_t xqc_get_random(xqc_random_generator_t *rand_gen, u_char *buf, size_t need_len);
xqc_random_generator_t *xqc_random_generator_create(xqc_log_t *log);
void xqc_random_generator_destroy(xqc_random_generator_t *rand_gen);


#endif /* _XQC_RANDOM_H_INCLUDED_ */

