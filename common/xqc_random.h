
#ifndef _XQC_RANDOM_H_INCLUDED_
#define _XQC_RANDOM_H_INCLUDED_

#include "xqc_str.h"
#include "xqc_log.h"

typedef struct xqc_random_generator_s{
    /* for random */
    xqc_int_t               rand_fd;           /* init_value: -1 */
    off_t                   rand_buf_offset;   /* used offset */
    size_t                  rand_buf_size;     /* total buffer size */
    xqc_str_t               rand_buf;          /* buffer for random bytes*/

    xqc_log_t              *log;
}xqc_random_generator_t;

xqc_int_t xqc_get_random(xqc_random_generator_t *rand_gen, u_char *buf, size_t need_len);
void xqc_random_generator_init(xqc_random_generator_t *rand_gen,
                                         xqc_log_t *log);

#endif /* _XQC_RANDOM_H_INCLUDED_ */

