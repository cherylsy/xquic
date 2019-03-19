#include <CUnit/CUnit.h>

#include "xqc_timer_test.h"

static void xqc_timer_cb(unsigned long data)
{
    printf("timer callback data:%lu now:%lu\n", data, xqc_gettimeofday());
}

void test_xqc_timer()
{
    xqc_timer_manager_t manager;
    xqc_timer_manager_init(&manager);

    xqc_timer_t t1, t2, t3;

    xqc_timer_init(&t1);
    xqc_timer_init(&t2);
    xqc_timer_init(&t3);

    t1.function = &xqc_timer_cb; t1.data = 1000;
    t2.function = &xqc_timer_cb; t2.data = 2000;
    t3.function = &xqc_timer_cb; t3.data = 200;

    xqc_timer_manager_add(&manager, &t1, 1000);
    xqc_timer_manager_add(&manager, &t2, 2000);
    xqc_timer_manager_add(&manager, &t3, 200);

    unsigned long time1 = xqc_gettimeofday() / 1000;

    while (1) {
        xqc_timer_manager_tick(&manager);

        unsigned long time2 = xqc_gettimeofday() / 1000;
        if (time2 - time1 > 3) { /*假定程序运行3秒后退出*/
            break;
        }
    }
}

