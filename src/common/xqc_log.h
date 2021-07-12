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

#include <xquic/xquic.h>
#include "src/common/xqc_config.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_time.h"

/*
 * 目前只是标准输出
 * 先定义接口，后面再实现
 * 先xqc_log_init()构建xqc_log_t句柄
 * 再用xqc_log_debug/xqc_log_error等接口记录日志
 * */

typedef struct xqc_log_s
{
    xqc_log_level_t      log_level;         
    xqc_flag_t           log_timestamp; /* 1:add timestamp before log, 0:don't need timestamp */
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

const char* xqc_log_level_str(xqc_log_level_t level);
void xqc_log_time(char* buf);
void xqc_log_implement(xqc_log_t *log, unsigned level, const char *func, const char *fmt, ...);


#ifndef XQC_DISABLE_LOG
    #ifndef XQC_ONLY_ERROR_LOG
    #define xqc_log(log, level, ...) \
    do { \
        if ((log)->log_level >= level) { \
            xqc_log_implement(log, level, __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)
    #else
    #define xqc_log(log, level, ...) \
        do { \
            if (XQC_LOG_ERROR >= level) { \
                xqc_log_implement(log, level, __FUNCTION__, __VA_ARGS__); \
            } \
        } while (0)
    #endif
#else
#define xqc_log(log, level, ...)
#endif

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

extern const xqc_log_callbacks_t xqc_null_log_cb;

#endif /*_XQC_H_LOG_INCLUDED_*/

