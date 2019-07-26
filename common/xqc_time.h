#ifndef _XQC_TIME_H_INCLUDED_
#define _XQC_TIME_H_INCLUDED_

#include <sys/time.h>

static inline uint64_t xqc_now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000000 + tv.tv_usec;
    return  ul;
}

#endif /* _XQC_TIME_H_INCLUDED_ */

