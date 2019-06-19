#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <event2/event.h>
#include "xqc_cmake_config.h"
#include "../include/xquic_typedef.h"
#include "../include/xquic.h"
#include "../congestion_control/xqc_new_reno.h"

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500



typedef struct xqc_server_ctx_s {
    int fd;
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    struct sockaddr_in local_addr;
    socklen_t local_addrlen;
    struct sockaddr_in peer_addr;
    socklen_t peer_addrlen;
    uint64_t send_offset;
    xqc_stream_t *stream;
    struct event *ev_recv;
    struct event *ev_timer;
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;

static inline uint64_t now()
{
    /*获取毫秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return  ul;
}

int xqc_server_conn_notify(xqc_cid_t *cid, void *user_data) {

    DEBUG;
    return 0;
}

int xqc_server_write_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    char buff[1000] = {0};
    xqc_stream_send(stream, buff, sizeof(buff), 1);

    return 0;
}

int xqc_server_read_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    char buff[1000] = {0};
    size_t buff_size = 1000;

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        printf("xqc_stream_recv %lld, fin:%d\n", read, fin);
    } while (read > 0);

    /*ssize_t sent;
    if (fin) {
        sent = xqc_stream_send(stream, buff, buff_size, fin);
        printf("xqc_stream_send %lld \n", sent);
    }*/
    return 0;
}

ssize_t xqc_server_send(void *user_data, unsigned char *buf, size_t size) {
    DEBUG;
    ssize_t res;
    int fd = ctx.fd;
    printf("xqc_server_send size %zd\n",size);
    do {
        res = sendto(fd, buf, size, 0, (struct sockaddr*)&ctx.peer_addr, ctx.peer_addrlen);
        printf("xqc_server_send write %zd, %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));

    return res;
}

void xqc_client_wakeup(xqc_server_ctx_t *ctx)
{
    xqc_msec_t wake_after = xqc_engine_wakeup_after(ctx->engine);
    //printf("xqc_engine_wakeup_after %llu\n", wake_after);
    if (wake_after > 0) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000;
        tv.tv_usec = wake_after % 1000 * 1000;
        event_add(ctx->ev_timer, &tv);
        printf("xqc_engine_wakeup_after %llu ms, now %llu\n", wake_after, now());
    }
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

    ssize_t recv_size = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t recv_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    ctx->peer_addrlen = sizeof(ctx->peer_addr);
    recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr*)&ctx->peer_addr, &ctx->peer_addrlen);
    if (recv_size < 0) {
        printf("xqc_server_read_handler: recvmsg = %zd\n", recv_size);
        return;
    }

    printf("xqc_server_read_handler recv_size=%zd\n",recv_size);

    if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size, 
                            (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen, 
                            (struct sockaddr *)(&ctx->peer_addr), ctx->peer_addrlen, (xqc_msec_t)recv_time, ctx) != 0)
    {
        printf("xqc_server_read_handler: packet process err\n");
    }

    xqc_client_wakeup(ctx);
}


static void
xqc_server_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_write_handler(ctx);
    } else if (what & EV_READ) {
        xqc_server_read_handler(ctx);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}


static int xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in *saddr = &ctx.local_addr;
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

    memset(saddr, 0, sizeof(struct sockaddr_in));
    ctx.local_addrlen = sizeof(struct sockaddr_in);

    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);
    saddr->sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)) < 0) {
        printf("bind socket failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int
xqc_server_process_conns(xqc_server_ctx_t *ctx)
{
    int rc = xqc_engine_main_logic(ctx->engine);
    if (rc) {
        printf("xqc_engine_main_logic error %d\n", rc);
        return -1;
    }

    xqc_client_wakeup(ctx);
    return 0;
}

static void
xqc_server_timer_callback(int fd, short what, void *arg)
{
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    int rc = xqc_server_process_conns(ctx);
    if (rc) {
        printf("xqc_server_timer_callback error\n");
        return;
    }
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
            .cong_ctrl_callback = xqc_reno_cb,
    };
    xqc_engine_set_callback(ctx.engine, callback);

    eb = event_base_new();

    ctx.ev_timer = event_new(eb, -1, 0, xqc_server_timer_callback, &ctx);

    ctx.fd = xqc_server_create_socket(TEST_ADDR, TEST_PORT);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_recv = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_event_callback, &ctx);

    event_add(ctx.ev_recv, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
