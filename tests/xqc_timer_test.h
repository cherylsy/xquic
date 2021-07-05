#ifndef xqc_timer_test_h
#define xqc_timer_test_h

#include "src/common/xqc_timer.h"

void xqc_test_timer();

inline xqc_usec_t 
xqc_test_now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    xqc_usec_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return ul;
}


#endif
