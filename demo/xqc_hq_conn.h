#ifndef XQC_HQ_CONN_H
#define XQC_HQ_CONN_H

#include "xqc_hq.h"

extern const xqc_conn_callbacks_t hq_conn_callbacks;

const xqc_cid_t *
xqc_hq_conn_get_cid(xqc_hq_conn_t *hqc);

#endif