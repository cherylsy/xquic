#ifndef xqc_common_test_h
#define xqc_common_test_h

#include "src/common/xqc_queue.h"
#include "src/common/xqc_hash.h"
#include "xquic/xquic.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"

void xqc_test_common();
const xqc_cid_t* test_cid_connect(xqc_engine_t *engine);
xqc_connection_t* test_engine_connect();
xqc_engine_t* test_create_engine();


#endif
