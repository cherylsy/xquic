#include "xqc_log.h"

void* xqc_open_log_file_default()
{
    ssize_t fd = open("./log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (fd < 0) {
        return NULL;
    }
    return (void*)fd;
}

int xqc_close_log_file_default(void *handler)
{
    int fd = (ssize_t)handler;
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

ssize_t xqc_write_log_file_default(void *handler, const void *buf, size_t count)
{
    int fd = (ssize_t)handler;
    if (fd < 0) {
        return -1;
    }
    return write(fd, buf, count);
}

xqc_log_callbacks_t default_log_cb = {
        .xqc_open_log_file = xqc_open_log_file_default,
        .xqc_close_log_file = xqc_close_log_file_default,
        .xqc_write_log_file = xqc_write_log_file_default,
        .log_level = XQC_LOG_DEBUG,
};