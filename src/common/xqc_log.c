#include "xqc_log.h"

#ifdef PRINT_MALLOC
FILE *g_malloc_info_fp;
#endif

int 
xqc_open_log_file_default(void *user_data)
{
    return 0;
}

int 
xqc_close_log_file_default(void *user_data)
{
    return 0;
}

ssize_t 
xqc_write_log_file_default(void *user_data, const void *buf, size_t count)
{
    return 0;
}

xqc_log_callbacks_t xqc_null_log_cb = {
        .xqc_open_log_file = xqc_open_log_file_default,
        .xqc_close_log_file = xqc_close_log_file_default,
        .xqc_write_log_file = xqc_write_log_file_default,
        .log_level = XQC_LOG_STATS,
};

const char*
xqc_log_level_str(xqc_log_level_t level)
{
    if (level == XQC_LOG_STATS) {
        return "stats";
    } else if (level == XQC_LOG_REPORT) {
        return "report";
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

void
xqc_log_implement(xqc_log_t *log, unsigned level, const char *func, const char *fmt, ...)
{
    unsigned char buf[2048];
    unsigned char *p = buf;
    unsigned char *last = buf + sizeof(buf);

    /* do not need time & level if use outside log format */
    if (log->log_callbacks->xqc_log_write_err == NULL) {
        /* time */
        char time[64];
        xqc_log_time(time);
        p = xqc_sprintf(p, last, "[%s] ", time);

        /* log level */
        p = xqc_sprintf(p, last, "[%s] ", xqc_log_level_str(level));
    }

    p = xqc_sprintf(p, last, "|%s", func);

    /* log */
    va_list args;
    va_start(args, fmt);
    p = xqc_vsprintf(p, last, fmt, args);
    va_end(args);

    if (p + 2 < last) {
        /* \n */
        *p++ = '\n';
        /* may use printf("%s") outside, add '\0' and don't count into size */
        *p = '\0';
    }

    /* XQC_LOG_STATS & XQC_LOG_REPORT are levels for statistic */
    if ((level == XQC_LOG_STATS || level == XQC_LOG_REPORT)
        && log->log_callbacks->xqc_log_write_stat)
    {
        log->log_callbacks->xqc_log_write_stat(log->user_data, buf, p - buf);

    } else if (log->log_callbacks->xqc_log_write_err) {
        log->log_callbacks->xqc_log_write_err(log->user_data, buf, p - buf);

    } else {
        log->log_callbacks->xqc_write_log_file(log->user_data, buf, p - buf);
    }
}

void
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
