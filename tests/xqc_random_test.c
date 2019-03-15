
#include <CUnit/CUnit.h>
#include "../common/xqc_random.h"
#include "../common/xqc_common.h"

void test_xqc_random()
{
    u_char buf[1024];
    xqc_random_generator_t rand_gen;
    xqc_log_t log;
    
    xqc_random_generator_init(&rand_gen, &log);

    int ret = xqc_get_random(&rand_gen, buf, 1024);

    CU_ASSERT(ret == XQC_OK);
}
