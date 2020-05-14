#ifndef _XQC_H_LOG_INCLUDED_
#define _XQC_H_LOG_INCLUDED_

#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "xqc_config.h"
#include "xqc_malloc.h"
#include "xqc_str.h"
#include "include/xquic.h"
#include "xqc_time.h"

/*
 * 目前只是标准输出
 * 先定义接口，后面再实现
 * 先xqc_log_init()构建xqc_log_t句柄
 * 再用xqc_log_debug/xqc_log_error等接口记录日志
 * */


static inline const char*
xqc_log_leveL_str(xqc_log_level_t level)
{
    if (level == XQC_LOG_STATS) {
        return "stats";
    } else if (level == XQC_LOG_FATAL) {
        return "fatal";
    } else if (level == XQC_LOG_ERROR) {
        return "error";
    } else if (level == XQC_LOG_WARN) {
        return "warn";
    } else if (level == XQC_LOG_INFO) {
        return "info";
    } else if (level == XQC_LOG_DEBUG) {
        return "debug";
    } else {
        return "unknown";
    }
}

typedef struct xqc_log_s
{
    unsigned log_level; /*日志级别*/
    xqc_log_callbacks_t *log_callbacks;
    void *user_data;
} xqc_log_t;

static inline xqc_log_t *
xqc_log_init(xqc_log_callbacks_t *log_callbacks, void *user_data)
{
    xqc_log_t* log = xqc_malloc(sizeof(xqc_log_t));
    log->log_level = log_callbacks->log_level;
    log->user_data = user_data;

    int ret = log_callbacks->xqc_open_log_file(user_data);
    if (ret < 0) {
        printf("open file failed\n");
        xqc_free(log);
        return NULL;
    }
    log->log_callbacks = log_callbacks;
    return log;
}

static inline void
xqc_log_release(xqc_log_t* log)
{
    log->log_callbacks->xqc_close_log_file(log->user_data);
    xqc_free(log);
    log = NULL;
}

static inline void
xqc_log_time(char* buf)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm tm;

#ifdef WIN32
    time_t t = tv.tv_sec;
#ifdef _USE_32BIT_TIME_T
	_localtime32_s(&tm, &t);
#else
	_localtime64_s(&tm, &t);
#endif

#else
    localtime_r(&tv.tv_sec, &tm);
#endif
    tm.tm_mon++;
    tm.tm_year += 1900;

#ifdef __APPLE__
    sprintf(buf, "%4d/%02d/%02d %02d:%02d:%02d %06d",
                tm.tm_year, tm.tm_mon,
                tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec, tv.tv_usec);
#else
    sprintf(buf, "%4d/%02d/%02d %02d:%02d:%02d %06ld",
            tm.tm_year, tm.tm_mon,
            tm.tm_mday, tm.tm_hour,
            tm.tm_min, tm.tm_sec, tv.tv_usec);
#endif
}

static inline void
xqc_log_implement(xqc_log_t *log, unsigned level,const char *func, const char *fmt, ...)
{
    unsigned char buf[2048];
    unsigned char *p = buf;
    unsigned char *last = buf + sizeof(buf);

    /*时间*/
    char time[64];
    xqc_log_time(time);
    p = xqc_sprintf(p, last, "[%s] ", time);
    // struct timeval tv;
    // gettimeofday(&tv, NULL);
    // p = xqc_sprintf(p, last, "[%ud.%06ud] ", tv.tv_sec, tv.tv_usec);

    /*日志等级*/
    p = xqc_sprintf(p, last, "[%s] ", xqc_log_leveL_str(level));

    p = xqc_sprintf(p, last, "|%s", func);

    /*日志内容*/
    va_list args;
    va_start(args, fmt);
    p = xqc_vsprintf(p, last, fmt, args);
    va_end(args);

    /*换行*/
    *p++ = '\n';
    /*外部有可能用printf %s打印，加上结束符，不计入总字节数中*/
    *p = '\0';

    log->log_callbacks->xqc_write_log_file(log->user_data, buf, p - buf);
}


#define xqc_log(log, level, ...) \
    do { \
        if ((log)->log_level >= level) { \
            xqc_log_implement(log, level, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)


#define xqc_conn_log(conn, level, fmt, ...) \
    xqc_log(conn->log, level, "|%s " fmt, xqc_conn_addr_str(conn), __VA_ARGS__ )


#define xqc_log_fatal(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_FATAL) { \
            xqc_log_implement(log, XQC_LOG_FATAL, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_error(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_ERROR) { \
            xqc_log_implement(log, XQC_LOG_ERROR, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_warn(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_WARN) { \
            xqc_log_implement(log, XQC_LOG_WARN, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_info(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_INFO) { \
            xqc_log_implement(log, XQC_LOG_INFO, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_debug(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_DEBUG) { \
            xqc_log_implement(log, XQC_LOG_DEBUG, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

extern xqc_log_callbacks_t null_log_cb;

#endif /*_XQC_H_LOG_INCLUDED_*/

