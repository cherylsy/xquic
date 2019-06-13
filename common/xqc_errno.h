
#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_


#include <errno.h>
#include <include/xquic.h>


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
#define XQC_ENOBUF          600
#define XQC_EVINTREAD       601
#define XQC_ENULLPTR        602
#define XQC_EMALLOC         603
#define XQC_EILLPKT         604
#define XQC_ELEVEL          605
#define XQC_EOFFSET         606
#define XQC_CLOSING         607
#define XQC_ECONN_NFOUND    608
#define XQC_ESYS            609

/* For QUIC ssl 7xx */


/* For QUIC application 8xx */

#define xqc_errno                  errno
#define xqc_socket_errno           errno
#define xqc_set_errno(err)         errno = err
#define xqc_set_socket_errno(err)  errno = err



#endif /* _XQC_ERRNO_H_INCLUDED_ */

