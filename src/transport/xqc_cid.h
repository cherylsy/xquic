
#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/common/xqc_list.h"


#define XQC_DEFAULT_CID_LEN 8

typedef enum {
    XQC_CID_UNUSED, 
    XQC_CID_USED,
    XQC_CID_RETIRED,
    XQC_CID_REMOVED,
} xqc_cid_state_t;


typedef struct xqc_cid_inner_s
{
    xqc_list_head_t   list;

    xqc_cid_t         cid;
    xqc_cid_state_t   state;
    xqc_usec_t        retired_ts;
} xqc_cid_inner_t;


typedef struct xqc_scid_set_s
{
    xqc_cid_t         user_scid; // one of the USED SCIDs, for create/close notify
    xqc_list_head_t   list_head; // a set of SCID, includes used/unused/retired SCID

    uint64_t          largest_scid_seq_num;
    uint32_t          unused_cnt;
    uint32_t          retired_cnt;
} xqc_scid_set_t;

typedef struct xqc_dcid_set_s
{
    xqc_cid_t         current_dcid; // one of the USED DCIDs, for send packets
    xqc_list_head_t   list_head;    // a set of DCID, includes used/unused/retired DCID

    uint64_t          largest_retire_prior_to;
    uint32_t          unused_cnt;
    uint32_t          retired_cnt;
    unsigned char     dcid_str[XQC_MAX_CID_LEN * 2 + 1];
} xqc_dcid_set_t;


xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *ori_cid, xqc_cid_t *cid,
    uint64_t cid_seq_num);


void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_init_zero(xqc_cid_t *cid);
void xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len);

void xqc_init_scid_set(xqc_scid_set_t *scid_set);
void xqc_init_dcid_set(xqc_dcid_set_t *dcid_set);
void xqc_destroy_scid_set(xqc_scid_set_t *scid_set);
void xqc_destroy_dcid_set(xqc_dcid_set_t *dcid_set);

xqc_int_t xqc_scid_set_insert_cid(xqc_scid_set_t *scid_set, xqc_cid_t *cid, xqc_cid_state_t state);
xqc_int_t xqc_dcid_set_insert_cid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid, xqc_cid_state_t state);
xqc_int_t xqc_scid_set_delete_cid(xqc_scid_set_t *scid_set, xqc_cid_t *cid);
xqc_int_t xqc_dcid_set_delete_cid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid);
xqc_cid_inner_t* xqc_cid_in_scid_set(const xqc_cid_t *cid, const xqc_scid_set_t *scid_set);
xqc_cid_inner_t* xqc_cid_in_dcid_set(const xqc_cid_t *cid, const xqc_dcid_set_t *dcid_set);

xqc_int_t xqc_scid_switch_to_next_state(xqc_scid_set_t *scid_set, xqc_cid_inner_t *scid);
xqc_int_t xqc_dcid_switch_to_next_state(xqc_dcid_set_t *dcid_set, xqc_cid_inner_t *dcid);

xqc_int_t xqc_get_unused_dcid(xqc_dcid_set_t *dcid_set, xqc_cid_t *cid);
xqc_int_t xqc_get_unused_scid(xqc_scid_set_t *scid_set, xqc_cid_t *cid);
xqc_cid_t* xqc_get_dcid_by_seq(xqc_dcid_set_t *dcid_set, uint64_t seq_num);
xqc_cid_t* xqc_get_scid_by_seq(xqc_scid_set_t *scid_set, uint64_t seq_num);

#endif /* _XQC_CID_H_INCLUDED_ */

