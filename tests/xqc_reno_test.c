
#include "xqc_reno_test.h"
#include "src/congestion_control/xqc_new_reno.h"
#include <stdio.h>
#include "src/common/xqc_time.h"
void
print_reno (xqc_new_reno_t *reno)
{

#ifdef DEBUG_PRINT
    printf("cwnd:%u, ssthresh:%u, recovery_start_time:%llu\n",
           reno->reno_congestion_window, reno->reno_ssthresh, reno->reno_recovery_start_time);
#endif
}

void
xqc_test_reno ()
{
    xqc_msec_t now = xqc_now();

    xqc_new_reno_t reno;
    xqc_msec_t delay = 100;
    xqc_cc_params_t params = {.init_cwnd = 10};
    xqc_reno_cb.xqc_cong_ctl_init(&reno, params);
    print_reno(&reno);

    //slow start
    for (int i = 0; i < 10; ++i) {
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, now, now + delay, 1000);
        now += 1000000;
        print_reno(&reno);
    }

    //lost
    xqc_reno_cb.xqc_cong_ctl_on_lost(&reno, now);
    print_reno(&reno);

    //congestion avoid
    for (int i = 0; i < 10; ++i) {
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, now, now + delay, 1000);
        now += 1000000;
        print_reno(&reno);
    }

    xqc_reno_cb.xqc_cong_ctl_reset_cwnd(&reno);
    print_reno(&reno);

}