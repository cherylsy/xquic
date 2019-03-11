#ifndef _XQC_H_LOG_INCLUDED_
#define _XQC_H_LOG_INCLUDED_

#include <stdarg.h>

#include "xqc_malloc.h"

/*
 * 目前只是标准输出
 * 先定义接口，后面再实现
 * 先xqc_log_init()构建xqc_log_t句柄
 * 再用xqc_log_debug/xqc_log_error等接口记录日志
 * */

enum xqc_log_level_t
{
    XQC_LOG_ERROR,
    XQC_LOG_WARN,
    XQC_LOG_INFO,
    XQC_LOG_DEBUG,
};

static inline const char* xqc_log_leveL_str(enum xqc_log_level_t level)
{
    if (level == XQC_LOG_ERROR) {
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
    int file_handle;
} xqc_log_t;

static inline xqc_log_t *xqc_log_init()
{
    xqc_log_t* log = xqc_malloc(sizeof(xqc_log_t));
    log->file_handle = 0;
    return log;
}

static inline void xqc_log_release(xqc_log_t* log)
{
    xqc_free(log);
    log = NULL;
}

static inline void xqc_log_core(enum xqc_log_level_t level, xqc_log_t *log, const char* fmt, ...)
{
    /*char buf[2048] = {};

    va_list args;
    va_start(args, fmt);
    snprintf(buf, sizeof(buf), fmt, args);
    va_end(args);*/

    printf("[%s] %s\n", xqc_log_leveL_str(level), __VA_ARGS__);
}

#define xqc_log_error(log, fmt, ...) xqc_log_core(XQC_LOG_ERROR, log, fmt, __VA_ARGS__)

#define xqc_log_warn(log, fmt, ...) xqc_log_core(XQC_LOG_WARN, log, fmt, __VA_ARGS__)

#define xqc_log_info(log, fmt, ...) xqc_log_core(XQC_LOG_INFO, log, fmt, __VA_ARGS__)

#define xqc_log_debug(log, fmt, ...) xqc_log_core(XQC_LOG_DEBUG, log, fmt, __VA_ARGS__)

#endif /*_XQC_H_LOG_INCLUDED_*/

