
#include "xqc_cubic_test.h"
#include "congestion_control/xqc_cubic.h"
#include <stdio.h>
#include "common/xqc_time.h"
void
print_cubic (xqc_cubic_t *cubic)
{

#ifdef DEBUG_PRINT
    printf("cwnd:%llu, tcp_cwnd:%llu, last_max_cwnd:%llu, ssthresh:%llu, epoch_start:%llu, bic_origin_point:%llu\n",
           cubic->cwnd, cubic->tcp_cwnd, cubic->last_max_cwnd, cubic->ssthresh, cubic->epoch_start, cubic->bic_origin_point);
#endif
}

void
xqc_test_cubic ()
{
    xqc_msec_t now = xqc_now();

    xqc_cubic_t cubic;
    xqc_msec_t delay = 100;
    xqc_cc_params_t params = {.init_cwnd = 10};
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, params);

    print_cubic(&cubic);

    //slow start
    for (int i = 0; i < 10; ++i) {
        xqc_cubic_cb.xqc_cong_ctl_on_ack(&cubic, now, now + delay, 1000);
        now += 1000000;
        print_cubic(&cubic);
    }

    //lost
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, now);
    print_cubic(&cubic);

    //congestion avoid
    for (int i = 0; i < 10; ++i) {
        xqc_cubic_cb.xqc_cong_ctl_on_ack(&cubic, now, now + delay, 1000);
        now += 1000000;
        print_cubic(&cubic);
    }

    xqc_cubic_cb.xqc_cong_ctl_reset_cwnd(&cubic);
    print_cubic(&cubic);

}