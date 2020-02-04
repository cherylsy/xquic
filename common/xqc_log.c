#include "xqc_log.h"

int xqc_open_log_file_default(void *user_data)
{
    return 0;
}

int xqc_close_log_file_default(void *user_data)
{
    return 0;
}

ssize_t xqc_write_log_file_default(void *user_data, const void *buf, size_t count)
{
    return 0;
}

xqc_log_callbacks_t null_log_cb = {
        .xqc_open_log_file = xqc_open_log_file_default,
        .xqc_close_log_file = xqc_close_log_file_default,
        .xqc_write_log_file = xqc_write_log_file_default,
        .log_level = XQC_LOG_DEBUG,
};