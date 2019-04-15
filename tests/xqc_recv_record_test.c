
#include "xqc_recv_record_test.h"
#include "../transport/xqc_packet.h"
#include <string.h>
#include <CUnit/CUnit.h>
#include <stdio.h>

void xqc_test_recv_record ()
{
    xqc_list_head_t *pos;
    xqc_pktno_range_node_t *pnode;
    xqc_recv_record_t record;
    xqc_init_list_head(&record.list_head);

    xqc_recv_record_add(&record, 0, 0);
    xqc_recv_record_add(&record, 1, 0);
    xqc_recv_record_add(&record, 10, 0);
    xqc_recv_record_add(&record, 2, 0);

    xqc_list_for_each(pos, &record.list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        //printf("low:%llu, high=%llu\n", pnode->pktno_range.low, pnode->pktno_range.high);
    }

    //printf("largest=%llu\n",xqc_recv_record_largest(&record));
    CU_ASSERT(10 == xqc_recv_record_largest(&record));
}
