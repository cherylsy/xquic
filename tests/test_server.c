#include <stdio.h>
#include <errno.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include <event2/event.h>
#include <memory.h>

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define max_pkt_num 10
char send_buff[max_pkt_num][1500];
size_t send_buff_len[max_pkt_num];
int send_buff_idx = 0;
unsignd char recv_buf[1500];


typedef struct xqc_server_ctx_s {
    int fd;
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    struct sockaddr *local_addr;
    socklen_t local_addrlen;
    struct sockaddr *peer_addr;
    socklen_t peer_addrlen;
    uint64_t send_offset;
    xqc_stream_t *stream;
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;

int xqc_server_conn_notify(void *user_data, xqc_connection_t *conn) {
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    ctx->stream = xqc_create_stream(conn, user_data);
    return 0;
}

int xqc_server_write_notify(void *user_data, xqc_stream_t *stream) {
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    char buff[1000] = {0};
    xqc_stream_send(stream, buff, sizeof(buff), 1);

    return 0;
}

int xqc_server_read_notify(void *user_data, xqc_stream_t *stream) {
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[100] = {0};


    return 0;
}

ssize_t xqc_server_send(xqc_connection_t *c, unsigned char *buf, size_t size) {
    DEBUG;
    if (send_buff_idx >= max_pkt_num) {
        printf("exceed max_pkt_num\n");
        return -1;
    }
    memset(send_buff[send_buff_idx], 0, sizeof(send_buff[send_buff_idx]));
    memcpy(send_buff[send_buff_idx], buf, size);
    send_buff_len[send_buff_idx] = size;
    printf("=> send_buff_size %zu\n", send_buff_len[send_buff_idx]);
    send_buff_idx++;
    return size;
}


void 
xqc_server_write_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
}


void 
xqc_server_read_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
    size_t recv_size = 0;

    xqc_msec_t recv_time = xqc_gettimeofday();

    if (xqc_engine_packet_process(ctx->engine, recv_buf, recv_size, 
                            ctx->local_addr, ctx->local_addrlen, 
                            ctx->peer_addr, ctx->peer_addrlen, recv_time) != XQC_OK)
    {
        xqc_log(ctx->engine->log, XQC_LOG_DEBUG, "|xqc_server_read_handler|packet process err|");
    }
}


static void
xqc_server_event_callback(int fd, short what, void *arg)
{
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_write_handler(ctx);
    } else if (what & EV_READ) {
        xqc_server_read_handler(ctx);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }

    struct event *ev_tmo = event_new(eb, -1, 0, recv_handler, ctx);
    struct timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;
    event_add(ev_tmo, &t);
}


static int xqc_create_socket(const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in saddr;
    struct hostent *ent;
    int optval;

    ent = gethostbyname(addr);
    if (ent == NULL) {
        printf("can not resolve host name: %s\n", addr);
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr = *((struct in_addr *)ent->h_addr);

    if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        printf("bind socket failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}


int main(int argc, char *argv[]) {
    printf("Usage: %s\n", argv[0], XQC_QUIC_VERSION);

    int rc;

    memset(&ctx, 0, sizeof(ctx));

    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER);

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_server_conn_notify,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_server_write_notify,
                    .stream_read_notify = xqc_server_read_notify,
            },
            .write_socket = xqc_server_send,
    };
    xqc_engine_set_callback(ctx.engine, callback);

    eb = event_base_new();

    ctx.fd = xqc_create_socket(TEST_ADDR, TEST_PORT);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    struct event *ev_tmo = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_event_callback, &ctx);
    struct timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;
    event_add(ev_tmo, &t);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
