#ifndef _XQC_BUF_H_INCLUDED_
#define _XQC_BUF_H_INCLUDED_

typedef struct {
    u_char      *pos;
    u_char      *last;

    u_char      *start;
    u_char      *end;

}xqc_buf_t;

#endif /* _XQC_BUF_H_INCLUDED_ */

