#ifndef _XQC_H3_H_
#define _XQC_H3_H_

#include "src/common/xqc_common_inc.h"
#include "src/http3/xqc_h3_defs.h"


typedef struct xqc_var_buf_s {
    /* buffer */
    unsigned char  *data;

    /* the size of buffer */
    size_t          buf_len;

    /* used length */
    size_t          data_len;

    /* length processed */
    size_t          consumed_len;

    /* finish flag */
    uint8_t         fin_flag;

    /* limit of memory malloc, if set to 0, regarded as infinite */
    size_t          limit;
} xqc_var_buf_t;

typedef struct xqc_list_buf_s {
    xqc_list_head_t list_head;
    xqc_var_buf_t  *buf;
} xqc_list_buf_t;


xqc_var_buf_t *
xqc_var_buf_create(size_t capacity);

xqc_var_buf_t *
xqc_var_buf_create_with_limit(size_t capacity, size_t limit);

void
xqc_var_buf_clear(xqc_var_buf_t *buf);


void
xqc_var_buf_free(xqc_var_buf_t *buf);



xqc_int_t
xqc_var_buf_realloc(xqc_var_buf_t *buf, size_t cap);

xqc_int_t
xqc_var_buf_cut(xqc_var_buf_t *buf);

/* take over buffer from xqc_var_buf_t */
unsigned char*
xqc_var_buf_take_over(xqc_var_buf_t *buf);

xqc_int_t
xqc_var_buf_save_data(xqc_var_buf_t *buf, const uint8_t *data, size_t data_len);


xqc_int_t
xqc_var_buf_save_prepare(xqc_var_buf_t *buf, size_t data_len);


xqc_list_buf_t *
xqc_list_buf_create(xqc_var_buf_t *buf);


void
xqc_list_buf_free(xqc_list_buf_t *list_buf);

void
xqc_list_buf_list_free(xqc_list_head_t *head_list);

xqc_int_t
xqc_list_buf_to_tail(xqc_list_head_t *phead, xqc_var_buf_t *buf);

#endif
