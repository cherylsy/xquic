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

#define max_pkt_num 10
#define XQC_PACKET_TMP_BUF_LEN 1500

char send_buff[max_pkt_num][XQC_PACKET_TMP_BUF_LEN];
size_t send_buff_len[max_pkt_num];
int send_buff_idx = 0;
unsigned char recv_buf[XQC_PACKET_TMP_BUF_LEN];


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
    struct event *event;    
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;

int xqc_server_conn_notify(xqc_connection_t *conn, void *user_data) {
    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    ctx->stream = xqc_create_stream(conn, user_data);
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
    char buff[100] = {0};


    return 0;
}

ssize_t xqc_server_send(void *user_data, unsigned char *buf, size_t size) {
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
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t recv_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    /* recv udp packet */
    ssize_t  n;
    struct iovec  iov[1];
    struct msghdr msg;    
    unsigned char msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    iov[0].iov_base = (void *) packet_buf;
    iov[0].iov_len = XQC_PACKET_TMP_BUF_LEN;

    msg.msg_name = &ctx->local_addr;
    msg.msg_namelen = ctx->local_addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (ctx->local_addr.sin_family == AF_INET) {
        msg.msg_control = &msg_control;
        msg.msg_controllen = sizeof(msg_control);
    }

    recv_size = recvmsg(ctx->fd, &msg, 0);

    if (recv_size < 0) {
        printf("xqc_server_read_handler: recvmsg = %z\n", recv_size);
        return;
    }

    if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size, 
                            (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen, 
                            (struct sockaddr *)(&ctx->peer_addr), ctx->peer_addrlen, (xqc_msec_t)recv_time) != 0)
    {
        printf("xqc_server_read_handler: packet process err\n");
    }
}


static void
xqc_server_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;
    struct timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;

    if (what & EV_TIMEOUT) {
        printf("event callback: timeout\n", what);
        event_add(ctx->event, &t);
        return;
    }

    if (what & EV_WRITE) {
        xqc_server_write_handler(ctx);
    } else if (what & EV_READ) {
        xqc_server_read_handler(ctx);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }

    event_add(ctx->event, &t);
}


static int xqc_create_socket(const char *addr, unsigned int port)
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
    saddr->sin_addr = *((struct in_addr *)ent->h_addr);

    if (bind(fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)) < 0) {
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
            .cong_ctrl_callback = xqc_reno_cb,
    };
    xqc_engine_set_callback(ctx.engine, callback);

    eb = event_base_new();

    ctx.fd = xqc_create_socket(TEST_ADDR, TEST_PORT);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    struct event *ev_tmo = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_event_callback, &ctx);
    ctx.event = ev_tmo;

    //struct timeval t;
    //t.tv_sec = 1;
    //t.tv_usec = 0;
    event_add(ev_tmo, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
