#ifndef _XQC_H3_CONN_H_INCLUDED_
#define _XQC_H3_CONN_H_INCLUDED_

#include "include/xquic_typedef.h"
#include "transport/xqc_conn.h"

typedef struct xqc_h3_conn_s xqc_h3_conn_t;

struct xqc_h3_conn_s {
    xqc_connection_t        *conn;
    xqc_log_t               *log;
    void                    *user_data;
};

extern const xqc_conn_callbacks_t conn_callbacks;

static inline void *
xqc_conn_get_user_data(xqc_connection_t *conn)
{
    if (conn->conn_settings.h3) {
        return ((xqc_h3_conn_t*)conn->user_data)->user_data;
    } else {
        return conn->user_data;
    }
}

xqc_h3_conn_t *
xqc_h3_conn_create(xqc_connection_t *conn, void *user_data);

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn);

int
xqc_conn_create_notify(xqc_connection_t *conn, void *user_data);

int
xqc_conn_close_notify(xqc_connection_t *conn, void *user_data);

#endif /* _XQC_H3_CONN_H_INCLUDED_ */
