#include <stdio.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include "../congestion_control/xqc_new_reno.h"
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <transport/xqc_stream.h>

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);


#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500


typedef struct user_conn_s {
    int                 fd;
    xqc_connection_t   *conn;

    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;

    xqc_stream_t       *stream;
} user_conn_t;

typedef struct client_ctx_s {
    xqc_engine_t  *engine;
    user_conn_t   *my_conn;
    struct event  *ev_recv;
    struct event  *ev_timer;
    struct event  *ev_timeout;
    uint64_t       send_offset;
} client_ctx_t;

client_ctx_t ctx;
struct event_base *eb;

static inline uint64_t now()
{
    /*获取毫秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return  ul;
}

ssize_t xqc_client_read_socket(void *user, unsigned char *buf, size_t size)
{
    user_conn_t *conn = (user_conn_t *) user;
    ssize_t res;
    int fd = conn->fd;

    do {
        res = read(fd, buf, size);
    } while ((res < 0) && (errno == EINTR));

    return res;
}


ssize_t xqc_client_write_socket(void *user, unsigned char *buf, size_t size)
{
    user_conn_t *conn = (user_conn_t *) user;
    ssize_t res;
    int fd = conn->fd;
    printf("xqc_client_write_socket size %zd\n",size);
    do {
        res = write(fd, buf, size);
        printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));

    return res;
}

static int xqc_client_create_socket(const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in saddr;
    struct hostent *remote;

    remote = gethostbyname(addr);
    if (remote == NULL) {
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

    memset(&saddr, 0, sizeof(saddr));

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr = *((struct in_addr *)remote->h_addr);

    if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

  err:
    close(fd);
    return -1;
}


int xqc_client_conn_notify(xqc_connection_t *conn, void *user_data) {
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    user_conn->stream = xqc_create_stream(conn, user_data);

    return 0;
}

int xqc_client_write_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    int ret;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[5000] = {0};
    ret = xqc_stream_send(stream, buff, sizeof(buff), 1);


    return ret;
}

int xqc_client_read_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[100] = {0};

    char buff_send[5000] = {0};
    xqc_stream_send(stream, buff_send, sizeof(buff), 1);
    return 0;
}

void xqc_client_wakeup(client_ctx_t *ctx)
{
    xqc_msec_t wake_after = xqc_engine_wakeup_after(ctx->engine);
    printf("xqc_engine_wakeup_after %llu ms, now %llu\n", wake_after, now());
    if (wake_after > 0) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000;
        tv.tv_usec = wake_after % 1000 * 1000;
        event_add(ctx->ev_timer, &tv);
        //printf("xqc_engine_wakeup_after %llu ms, now %llu\n", wake_after, now());
    }
}

void 
xqc_client_write_handler(client_ctx_t *ctx)
{
    DEBUG
}


void 
xqc_client_read_handler(client_ctx_t *ctx)
{
    DEBUG

    ssize_t recv_size = 0;
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

    msg.msg_name = &ctx->my_conn->local_addr;
    msg.msg_namelen = ctx->my_conn->local_addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (ctx->my_conn->local_addr.sin_family == AF_INET) {
        msg.msg_control = &msg_control;
        msg.msg_controllen = sizeof(msg_control);
    }

    recv_size = recvmsg(ctx->my_conn->fd, &msg, 0);

    if (recv_size < 0) {
        printf("xqc_client_read_handler: recvmsg = %zd\n", recv_size);
        return;
    }

    printf("xqc_client_read_handler recv_size=%zd\n",recv_size);

    if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size, 
                            (struct sockaddr *)(&ctx->my_conn->local_addr), ctx->my_conn->local_addrlen, 
                            (struct sockaddr *)(&ctx->my_conn->peer_addr), ctx->my_conn->peer_addrlen, (xqc_msec_t)recv_time) != 0)
    {
        printf("xqc_client_read_handler: packet process err\n");
    }

    xqc_client_wakeup(ctx);
}


static void
xqc_client_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_client_write_handler(ctx);
    } else if (what & EV_READ) {
        xqc_client_read_handler(ctx);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

static int
xqc_client_process_conns(client_ctx_t *ctx)
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
xqc_client_timer_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timer_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    int rc = xqc_client_process_conns(ctx);
    if (rc) {
        printf("xqc_client_timer_callback error\n");
        return;
    }
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timeout_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;
    int rc;
    rc = xqc_conn_close(ctx->my_conn->conn);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }

    rc = xqc_client_process_conns(ctx);
    if (rc) {
        printf("xqc_client_timer_callback error\n");
        return;
    }
    //event_base_loopbreak(eb);
}

int main(int argc, char *argv[]) {
    printf("Usage: %s XQC_QUIC_VERSION:%d\n", argv[0], XQC_QUIC_VERSION);

    int rc;

    char server_addr[64] = TEST_SERVER_ADDR;
    int server_port = TEST_SERVER_PORT;

    int ch = 0;
    while((ch = getopt(argc, argv, "a:p:")) != -1){
        switch(ch)
        {
            case 'a':
                printf("option a:'%s'\n", optarg);
                snprintf(server_addr, sizeof(server_addr), optarg);
                break;
            case 'p':
                printf("option port :%s\n", optarg);
                server_port = atoi(optarg);
                break;

            default:
                printf("other option :%c\n", ch);
                exit(0);
        }

    }

    memset(&ctx, 0, sizeof(ctx));

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT);

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_client_conn_notify,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_client_write_notify,
                    .stream_read_notify = xqc_client_read_notify,
            },
            .read_socket = xqc_client_read_socket,
            .write_socket = xqc_client_write_socket,
            .cong_ctrl_callback = xqc_reno_cb,
    };
    xqc_engine_set_callback(ctx.engine, callback);

    ctx.my_conn = malloc(sizeof(user_conn_t));
    if (ctx.my_conn == NULL) {
        printf("xqc_malloc error\n");
        return 0;
    }

    ctx.my_conn->fd = xqc_client_create_socket(server_addr, server_port);
    if (ctx.my_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.my_conn->conn = xqc_connect(ctx.engine, ctx.my_conn);
    if (ctx.my_conn->conn == NULL) {
        printf("xqc_connect error\n");
        return 0;
    }

    eb = event_base_new();

    ctx.ev_timer = event_new(eb, -1, 0, xqc_client_timer_callback, &ctx);
    ctx.ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, &ctx);

    ctx.ev_recv = event_new(eb, ctx.my_conn->fd, EV_READ | EV_PERSIST, xqc_client_event_callback, &ctx);
    event_add(ctx.ev_recv, NULL);

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    event_add(ctx.ev_timeout, &tv);

    rc = xqc_client_process_conns(&ctx);
    if (rc) {
        printf("xqc_client_process_conns error\n");
        return 0;
    }

    event_base_dispatch(eb);

    /*xqc_client_write_notify(ctx.my_conn->stream, &ctx);
    DEBUG;*/

    xqc_engine_destroy(ctx.engine);
    return 0;
}
