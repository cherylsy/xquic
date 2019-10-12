#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <event2/event.h>
#include <arpa/inet.h>
#include "congestion_control/xqc_bbr.h"
#include "xqc_cmake_config.h"
#include "include/xquic_typedef.h"
#include "include/xquic.h"
#include "congestion_control/xqc_new_reno.h"

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
    struct event *ev_socket;
    struct event *ev_engine;
    int header_sent;
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;

static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000000 + tv.tv_usec;
    return  ul;
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

int xqc_server_conn_notify(xqc_connection_t *conn, void *user_data) {

    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
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
    } while (read > 0 && !fin);

    ssize_t sent;
    if (fin) {
        sent = xqc_stream_send(stream, buff, buff_size, fin);
        printf("xqc_stream_send %lld \n", sent);
    }
    return 0;
}

int xqc_server_h3_conn_notify(xqc_h3_conn_t *conn, void *user_data) {

    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    return 0;
}

int xqc_server_request_send(xqc_h3_request_t *h3_request, xqc_server_ctx_t *ctx)
{
    ssize_t ret = 0;
    xqc_http_header_t header[] = {
            {
                    .name   = {.iov_base = ":method", .iov_len = 7},
                    .value  = {.iov_base = "post", .iov_len = 4}
            },
    };
    xqc_http_headers_t headers = {
            .headers = header,
            .count  = 1,
    };

    if (ctx->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, 0);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %d\n", ret);
        } else {
            printf("xqc_h3_request_send_headers success size=%lld\n", ret);
            ctx->header_sent = 1;
        }
    }

    unsigned buff_size = 500*1024;
    char *buff = malloc(buff_size);
    if (ctx->send_offset < buff_size) {
        ret = xqc_h3_request_send_body(h3_request, buff + ctx->send_offset, buff_size - ctx->send_offset, 1);
        if (ret < 0) {
            printf("xqc_h3_request_send_body error %d\n", ret);
        } else {
            ctx->send_offset += ret;
            printf("xqc_h3_request_send_body offset=%lld\n", ctx->send_offset);
        }
    }
    return 0;
}

int xqc_server_request_create_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    int ret = 0;

    xqc_h3_request_set_user_data(h3_request, &ctx);

    return 0;
}

int xqc_server_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    int ret = 0;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    ret = xqc_server_request_send(h3_request, ctx);
    return ret;
}

int xqc_server_request_read_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    int ret;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    char buff[5000] = {0};
    size_t buff_size = 5000;

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        printf("xqc_h3_request_recv_body %lld, fin:%d\n", read, fin);
    } while (read > 0 && !fin);

    if (!fin) {
        return 0;
    }

    //xqc_server_request_send(h3_request, ctx);


    return 0;
}

ssize_t xqc_server_send(void *user_data, unsigned char *buf, size_t size) {
    DEBUG;
    ssize_t res;
    int fd = ctx.fd;
    printf("xqc_server_send size=%zd now=%llu\n",size, now());
    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, (struct sockaddr*)&ctx.peer_addr, ctx.peer_addrlen);
        printf("xqc_server_send write %zd, %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));

    return res;
}


void
xqc_server_write_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
}

int g_recv_total = 0;
void
xqc_server_read_handler(xqc_server_ctx_t *ctx)
{
    DEBUG

    ssize_t recv_size = 0;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    ctx->peer_addrlen = sizeof(ctx->peer_addr);

    do {
        recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &ctx->peer_addr,
                             &ctx->peer_addrlen);
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
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));
    */
        if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *) (&ctx->peer_addr), ctx->peer_addrlen, (xqc_msec_t) recv_time,
                                      ctx) != 0) {
            printf("xqc_server_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);
    xqc_engine_main_logic(ctx->engine);
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

    int size = 10 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
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


static void
xqc_server_engine_callback(int fd, short what, void *arg)
{
    DEBUG;
    printf("timer wakeup now=%lld\n", now());
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}


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


int main(int argc, char *argv[]) {
    printf("Usage: %s\n", argv[0], XQC_QUIC_VERSION);

    int rc;

    memset(&ctx, 0, sizeof(ctx));

    char g_key_file[] = "./server.key";
    char g_cert_file[] = "./server.crt";
    char g_session_ticket_file[] = "session_ticket.key";


    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;


    char g_session_ticket_key[2048];
    int ticket_key_len  = read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);

    if(ticket_key_len < 0){
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;
    }else{
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }


    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &engine_ssl_config);

    if(ctx.engine == NULL){
        printf("error create engine\n");
        return -1;
    }

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_server_conn_notify,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = xqc_server_h3_conn_notify,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_server_write_notify,
                    .stream_read_notify = xqc_server_read_notify,
            },
            .h3_request_callbacks = {
                    .h3_request_write_notify = xqc_server_request_write_notify,
                    .h3_request_read_notify = xqc_server_request_read_notify,
                    .h3_request_create = xqc_server_request_create_notify,
            },
            .write_socket = xqc_server_send,
            //.cong_ctrl_callback = xqc_reno_cb,
            .cong_ctrl_callback = xqc_bbr_cb,
            .set_event_timer = xqc_server_set_event_timer,
    };

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   0,
            .h3         =   1,
    };

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &ctx);

    xqc_engine_init(ctx.engine, callback, conn_settings, &ctx);

    ctx.fd = xqc_server_create_socket(TEST_ADDR, TEST_PORT);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_socket = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_event_callback, &ctx);

    event_add(ctx.ev_socket, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
