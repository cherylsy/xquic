#ifndef _XQC_TIME_H_INCLUDED_
#define _XQC_TIME_H_INCLUDED_

#ifndef WIN32
#include <sys/time.h>
#endif
#ifdef MINGW_HAS_SECURE_API
#include <sec_api/time_s.h>
#endif
#include <time.h>

#ifdef WIN32
#define DELTA_EPOCH_IN_TICKS  116444736000000000ULL

static int
gettimeofday (struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    uint64_t tmpres;
    static int tzflag;

    if (NULL != tv) {
        GetSystemTimeAsFileTime(&ft);

        tmpres = ((uint64_t) ft.dwHighDateTime << 32)
               | (ft.dwLowDateTime);

        tmpres -= DELTA_EPOCH_IN_TICKS;
        tv->tv_sec = tmpres / 10000000;
        tv->tv_usec = tmpres % 1000000;
    }

    if (NULL != tz) {
        if (!tzflag) {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}
#endif

static inline uint64_t xqc_now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}

#endif /* _XQC_TIME_H_INCLUDED_ */

