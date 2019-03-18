#ifndef _XQC_CLIENT_H_INCLUDED_
#define _XQC_CLIENT_H_INCLUDED_

#include "xqc_conn.h"

typedef struct xqc_client_connection_s {
    xqc_connection_t    *xc;

    void                *user_data;
}xqc_client_connection_t;


#endif /* _XQC_CLIENT_H_INCLUDED_ */

