
#include "xqc_multipath.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "xqc_engine.h"
#include "xqc_cid.h"
#include "xqc_stream.h"
#include "xqc_utils.h"
#include "xqc_wakeup_pq.h"

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_timer.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_id_hash.h"


/**
 * Check whether the connection supports multi-path or not.
 * @param conn  connection context
 * @return enable_multipath 0:not support, 1:support
 */
uint64_t
xqc_mp_is_support(xqc_connection_t *conn)
{
    return (conn->remote_settings.enable_multipath && conn->local_settings.enable_multipath);
}




