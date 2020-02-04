#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <event2/event.h>
#include "congestion_control/xqc_bbr.h"
#include "xqc_cmake_config.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "congestion_control/xqc_new_reno.h"
#include "axquic.h"

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443
#define XQC_PACKET_TMP_BUF_LEN 1500

typedef struct user_conn_s {
    xqc_connection_t    *conn;
    int                 fd;
#if 0
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;
#endif

    struct event        *ev_timeout;

} user_conn_t;

typedef struct xqc_server_ctx_s {
    int                 fd;
    xqc_engine_t        *engine;
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct event        *ev_engine;
    struct event        *ev_socket;
    int                 log_fd;
} xqc_server_ctx_t;

xqc_server_ctx_t g_ctx;
static uint64_t g_recv_total = 0;


int read_file_data( char * data, size_t data_len, char *filename){
    FILE * fp = fopen( filename, "rb");

    if(fp == NULL){
        return -1;
    }
    fseek(fp, 0 , SEEK_END);
    size_t total_len  = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if(total_len > data_len){
        return -1;
    }

    size_t read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len){

        return -1;
    }

    return read_len;

}

void xqc_server_set_event_timer(void *user_data, xqc_msec_t wake_after)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

int xqc_server_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data) {

    user_conn_t * user_conn = calloc(1, sizeof(*user_conn));
    xqc_conn_set_user_data(conn, user_conn);

    user_conn->conn = conn;

    xqc_server_ctx_t * ctx = user_data;
    user_conn->fd = ctx->fd; //all connections use one fd

    return 0;
}

int xqc_server_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data) {

    user_conn_t * user_conn = (user_conn_t *)user_data;
    free(user_conn);
    return 0;
}

int xqc_server_stream_write_notify(xqc_stream_t *stream, void *user_data) {


    axquic_client_stream_t * client_stream = (axquic_client_stream_t *)user_data;
    axquic_send_stream_buf(client_stream);

    return 0;
}

int xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    axquic_client_stream_t * client_stream = (axquic_client_stream_t *)user_data;
    ssize_t read;
    unsigned char fin;
    char buff[4096] = {0};
    size_t buff_size = sizeof(buff);
    do {
        read = axquic_recv(client_stream, buff, buff_size, &fin);
        printf("xqc_stream_recv %lld, fin:%d\n", read, fin);
    } while (read > 0 && !fin);

    if (fin) {
        //axquic_send(client_stream, buff, buff_size, fin);
    }
    return 0;
}


int xqc_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    int ret = 0;

    axquic_client_stream_t *client_stream = calloc(1, sizeof(axquic_client_stream_t));
    client_stream->stream = stream;
    xqc_stream_set_user_data(stream, client_stream);

    return 0;
}

int xqc_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    axquic_client_stream_t *client_stream = (axquic_client_stream_t*)user_data;
    free(client_stream);

    return 0;
}



ssize_t xqc_server_send(void *user_data, unsigned char *buf, size_t size, const struct sockaddr * peer_addr, socklen_t peer_addrlen) {
    ssize_t res;

    printf("xqc_server_send size=%zd now=%llu\n",size, now());

    int fd = g_ctx.fd;
    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, (struct sockaddr*)peer_addr, peer_addrlen);
        printf("xqc_server_send write %zd, %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));

    return res;
}

void xqc_server_write_handler(xqc_server_ctx_t *ctx)
{
    return;
}


void
xqc_server_read_handler(xqc_server_ctx_t *ctx)
{
    DEBUG

    ssize_t recv_size = 0;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    struct sockaddr peer_addr;
    socklen_t peer_addrlen;
    do {
        recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &peer_addr,
                             &peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            //printf("!!!!!!!!!errno EAGAIN\n");
            break;
        }
        if (recv_size < 0) {
            printf("!!!!!!!!!xqc_server_read_handler: recvmsg = %zd err=%s\n", recv_size, strerror(errno));
            break;
        }

        uint64_t recv_time = now();
        printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/
        if (axquic_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *) (&peer_addr), peer_addrlen, (xqc_msec_t) recv_time,
                                      ctx) != 0) {
            printf("xqc_server_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);
    xqc_engine_finish_recv(ctx->engine);
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



static int xqc_server_create_socket(xqc_server_ctx_t * ctx, const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in *saddr = &ctx->local_addr;
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
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    int size = 10 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }


    memset(saddr, 0, sizeof(struct sockaddr_in));
    ctx->local_addrlen = sizeof(struct sockaddr_in);

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


static void
xqc_server_engine_callback(int fd, short what, void *arg)
{
    DEBUG;
    printf("timer wakeup now=%lld\n", now());
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

int xqc_server_open_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    ctx->log_fd = open("./slog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int xqc_server_close_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

ssize_t xqc_server_write_log_file(void *engine_user_data, const void *buf, size_t count)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return write(ctx->log_fd, buf, count);
}

int main(int argc, char *argv[]) {

    char session_ticket_file[] = "session_ticket.key";
    char session_ticket_key[2048];
    int ticket_key_len  = read_file_data(session_ticket_key, sizeof(session_ticket_key), session_ticket_file);

    char * private_key_file = "./server.key";
    char * cert_file = "./server.crt";

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_server_conn_create_notify,
                    .conn_close_notify = xqc_server_conn_close_notify,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = NULL,
                    .h3_conn_close_notify = NULL,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_server_stream_write_notify,
                    .stream_read_notify = xqc_server_stream_read_notify,
                    .stream_create_notify = xqc_server_stream_create_notify,
                    .stream_close_notify = xqc_server_stream_close_notify,
            },
            .h3_request_callbacks = {
                    .h3_request_write_notify = NULL,
                    .h3_request_read_notify = NULL,
                    .h3_request_create_notify = NULL,
                    .h3_request_close_notify = NULL,
            },
            .write_socket = xqc_server_send,
            //.read_socket = xqc_send_recv,
            //.cong_ctrl_callback = xqc_reno_cb,
            .cong_ctrl_callback = xqc_bbr_cb,
            .set_event_timer = xqc_server_set_event_timer,
            .log_callbacks = {
                    .log_level = XQC_LOG_DEBUG,
                    //.log_level = XQC_LOG_ERROR,
                    .xqc_open_log_file = xqc_server_open_log_file,
                    .xqc_close_log_file = xqc_server_close_log_file,
                    .xqc_write_log_file = xqc_server_write_log_file,
            },
    };

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   0,
    };


    g_ctx.engine = axquic_server_initial_engine(callback, session_ticket_key, ticket_key_len,
            private_key_file, cert_file, &g_ctx);

    struct event_base *eb = event_base_new();

    g_ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &g_ctx);

    g_ctx.fd = xqc_server_create_socket(&g_ctx, TEST_ADDR, TEST_PORT);
    g_ctx.ev_socket = event_new(eb, g_ctx.fd, EV_READ | EV_PERSIST, xqc_server_event_callback, &g_ctx);

    event_add(g_ctx.ev_socket, NULL);
    event_base_dispatch(eb);

    xqc_engine_destroy(g_ctx.engine);
    return 0;
}
