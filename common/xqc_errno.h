
#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_


#include <errno.h>

typedef enum xqc_h3_err_code {
    HTTP_NO_ERROR                   = 0x00,
    HTTP_GENERAL_PROTOCOL_ERROR     = 0x01,
    HTTP_INTERNAL_ERROR             = 0x03,
    HTTP_REQUEST_CANCELLED          = 0x05,
    HTTP_INCOMPLETE_REQUEST         = 0x06,
    HTTP_CONNECT_ERROR              = 0x07,
    HTTP_EXCESSIVE_LOAD             = 0x08,
    HTTP_VERSION_FALLBACK           = 0x09,
    HTTP_WRONG_STREAM               = 0x0A,
    HTTP_ID_ERROR                   = 0x0B,
    HTTP_STREAM_CREATION_ERROR      = 0x0D,
    HTTP_CLOSED_CRITICAL_STREAM     = 0x0F,
    HTTP_EARLY_RESPONSE             = 0x0011,
    HTTP_MISSING_SETTINGS           = 0x0012,
    HTTP_UNEXPECTED_FRAME           = 0x0013,
    HTTP_REQUEST_REJECTED           = 0x0014,
    HTTP_SETTINGS_ERROR             = 0x00FF,
    HTTP_MALFORMED_FRAME            = 0x0100,
} xqc_h3_err_code_t;

typedef int               xqc_err_t;

/* For system call */
#define XQC_EPERM         EPERM
#define XQC_ENOENT        ENOENT
#define XQC_ENOPATH       ENOENT
#define XQC_ESRCH         ESRCH
#define XQC_EINTR         EINTR
#define XQC_ECHILD        ECHILD
#define XQC_ENOMEM        ENOMEM
#define XQC_EACCES        EACCES
#define XQC_EBUSY         EBUSY
#define XQC_EEXIST        EEXIST
#define XQC_EXDEV         EXDEV
#define XQC_ENOTDIR       ENOTDIR
#define XQC_EISDIR        EISDIR
#define XQC_EINVAL        EINVAL
#define XQC_ENFILE        ENFILE
#define XQC_EMFILE        EMFILE
#define XQC_ENOSPC        ENOSPC
#define XQC_EPIPE         EPIPE
#define XQC_EINPROGRESS   EINPROGRESS
#define XQC_ENOPROTOOPT   ENOPROTOOPT
#define XQC_EOPNOTSUPP    EOPNOTSUPP
#define XQC_EADDRINUSE    EADDRINUSE
#define XQC_ECONNABORTED  ECONNABORTED
#define XQC_ECONNRESET    ECONNRESET
#define XQC_ENOTCONN      ENOTCONN
#define XQC_ETIMEDOUT     ETIMEDOUT
#define XQC_ECONNREFUSED  ECONNREFUSED
#define XQC_ENAMETOOLONG  ENAMETOOLONG
#define XQC_ENETDOWN      ENETDOWN
#define XQC_ENETUNREACH   ENETUNREACH
#define XQC_EHOSTDOWN     EHOSTDOWN
#define XQC_EHOSTUNREACH  EHOSTUNREACH
#define XQC_ENOSYS        ENOSYS
#define XQC_ECANCELED     ECANCELED
#define XQC_EILSEQ        EILSEQ
#define XQC_ENOMOREFILES  0
#define XQC_ELOOP         ELOOP
#define XQC_EBADF         EBADF

#define XQC_EAGAIN        EAGAIN

/* For QUIC transport 6xx */
#define XQC_ENOBUF          600 //buf空间不足
#define XQC_EVINTREAD       601
#define XQC_ENULLPTR        602
#define XQC_EMALLOC         603
#define XQC_EILLPKT         604 //非法报文
#define XQC_ELEVEL          605 //加密等级错误
#define XQC_EOFFSET         606
#define XQC_CLOSING         607
#define XQC_ECONN_NFOUND    608
#define XQC_ESYS            609
#define XQC_EBLOCKED        610
#define XQC_EPARAM          611 //参数错误
#define XQC_ESTATE          612
#define XQC_ELIMIT          613 //超过协议限制
#define XQC_EPROTO          614 //违反协议规定
#define XQC_ESOCKET         615
#define XQC_EFATAL          616 //致命错误
#define XQC_ESTREAM_ST      617
#define XQC_ESEND_RETRY     618
#define XQC_ECONN_BLOCKED   619
#define XQC_ESTREAM_BLOCKED 620

/* For QUIC ssl 7xx */


/* For QUIC application 8xx */
#define XQC_H3_EMALLOC      800
#define XQC_H3_ESTREAM      801
#define XQC_H3_EREQUEST     802
#define XQC_H3_EGOAWAY      803




#endif /* _XQC_ERRNO_H_INCLUDED_ */

