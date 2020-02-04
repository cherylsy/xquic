#define _GNU_SOURCE
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <event2/event.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <netinet/udp.h>
#include "axquic.h"
#include "include/xquic_typedef.h"

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500

#define XQC_MAX_TOKEN_LEN 32


typedef struct user_conn_s{
    xqc_engine_t        *engine;
    xqc_cid_t           cid;

    int                 fd;

    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;

    struct event        *ev_socket;
    struct event        *ev_timeout;

    uint64_t            send_count;
} user_conn_t;


typedef struct client_ctx_s {
    xqc_engine_t  *engine;
    struct event  *ev_engine;
    struct event        *ev_socket;
    int            log_fd;
} client_ctx_t;


void xqc_client_set_event_timer(void *user_data, xqc_msec_t wake_after)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}


int save_session_cb( char * data, size_t data_len, void *user_data)
{
    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _session_cb error\n");
        return -1;
    }
    fclose(fp);
    return 0;
}


int save_tp_cb(char * data, size_t data_len, void * user_data)
{
    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _tp_cb error\n");
        return -1;
    }
    fclose(fp);
    return 0;
}

void xqc_client_save_token(void * user_data, const unsigned char *token, uint32_t token_len)
{
    int fd = open("./xqc_token",O_TRUNC|O_CREAT|O_WRONLY, S_IRWXU);
    if (fd < 0) {
        printf("save token error %s\n", strerror(errno));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(errno));
        close(fd);
        return;
    }
    close(fd);
}

int xqc_client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open("./xqc_token", O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(errno));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    printf("read token size %zu\n", n);
    printf("0x%x\n", token[0]);
    close(fd);
    return n;
}


static int xqc_client_create_socket(user_conn_t *user_conn, const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in *saddr = &user_conn->peer_addr;
    user_conn->peer_addrlen = sizeof(*saddr);
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

    memset(saddr, 0, sizeof(struct sockaddr_in));

    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);
    saddr->sin_addr = *((struct in_addr *)remote->h_addr);


    return fd;

  err:
    close(fd);
    return -1;
}


int xqc_client_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *) user_data;

    return 0;
}

int xqc_client_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *) user_data;
    free(user_conn);
    //event_base_loopbreak(eb);
    return 0;
}


int xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    int ret = 0;
    axquic_client_stream_t *client_stream = (axquic_client_stream_t *) user_data;
    ret = axquic_send_stream_buf(client_stream);
    return ret;
}



int xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    axquic_client_stream_t  *client_stream = (axquic_client_stream_t *) user_data;
    char buff[1500] = {0};
    size_t buff_size = sizeof(buff);

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        printf("xqc_stream_recv %lld, fin:%d\n", read, fin);
    } while (read > 0 && !fin);

    return 0;
}

int xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    axquic_client_stream_t *client_stream = (axquic_client_stream_t*)user_data;
    free(client_stream);
    return 0;
}


void xqc_client_read_handler(user_conn_t *user_conn)
{

    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    user_conn->peer_addrlen = sizeof(user_conn->peer_addr);

    do {
        recv_size = recvfrom(user_conn->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &user_conn->peer_addr,
                             &user_conn->peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            printf("xqc_client_read_handler: recvmsg = %zd(%s)\n", recv_size, strerror(errno));
            break;
        }
        uint64_t recv_time = now();
        printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n", recv_size, recv_time);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

        if (xqc_engine_packet_process(user_conn->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&user_conn->local_addr), user_conn->local_addrlen,
                                      (struct sockaddr *) (&user_conn->peer_addr), user_conn->peer_addrlen,
                                      (xqc_msec_t) recv_time, user_conn) != 0) {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);
    xqc_engine_finish_recv(user_conn->engine);
}


ssize_t xqc_client_write_socket(void *user_data, unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen){
    user_conn_t *user_conn = (user_conn_t *) user_data;
    ssize_t res;
    int fd = user_conn->fd;
    printf("xqc_client_write_socket size=%zd, now=%llu, send_total=%d\n",size, now(), ++user_conn->send_count);
    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
        }
    } while ((res < 0) && (errno == EINTR));
    return res;

}

void
xqc_client_write_handler(user_conn_t *user_conn)
{
    //DEBUG
    xqc_conn_continue_send(user_conn->engine, &user_conn->cid);
}


static void
xqc_client_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        xqc_client_write_handler(user_conn);
    } else if (what & EV_READ) {
        xqc_client_read_handler(user_conn);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}



static void
xqc_client_engine_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timer_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

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

int xqc_client_open_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    ctx->log_fd = open("./clog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int xqc_client_close_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

ssize_t xqc_client_write_log_file(void *engine_user_data, const void *buf, size_t count)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return write(ctx->log_fd, buf, count);
}


int main(int argc, char *argv[]) {
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

    client_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    struct event_base *eb;

    eb = event_base_new(); //初始化事件机制

    xqc_engine_callback_t callback = {
        .conn_callbacks = {
            .conn_create_notify = xqc_client_conn_create_notify,
            .conn_close_notify = xqc_client_conn_close_notify,
        },
        .h3_conn_callbacks = {
            .h3_conn_create_notify = NULL, /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
            .h3_conn_close_notify = NULL, /* 连接关闭时回调,用户可以回收资源 */
        },
        /* 仅使用传输层时实现 */
        .stream_callbacks = {
            .stream_write_notify = xqc_client_stream_write_notify, /* 可写时回调，用户可以继续调用写接口 */
            .stream_read_notify = xqc_client_stream_read_notify, /* 可读时回调，用户可以继续调用读接口 */
            .stream_close_notify = xqc_client_stream_close_notify, /* 关闭时回调，用户可以回收资源 */
        },
        /* 使用应用层时实现 */
        .h3_request_callbacks = {
            .h3_request_write_notify = NULL, /* 可写时回调，用户可以继续调用写接口 */
            .h3_request_read_notify = NULL, /* 可读时回调，用户可以继续调用读接口 */
            .h3_request_close_notify = NULL, /* 关闭时回调，用户可以回收资源 */
        },
        .write_socket = xqc_client_write_socket, /* 用户实现socket写接口 */
        .cong_ctrl_callback = xqc_reno_cb,
        .set_event_timer = xqc_client_set_event_timer, /* 设置定时器，定时器到期时调用xqc_engine_main_logic */
        .save_token = xqc_client_save_token, /* 保存token到本地，connect时带上 */
        .log_callbacks = {
                .log_level = XQC_LOG_DEBUG,
                //.log_level = XQC_LOG_ERROR,
                .xqc_open_log_file = xqc_client_open_log_file,
                .xqc_close_log_file = xqc_client_close_log_file,
                .xqc_write_log_file = xqc_client_write_log_file,
        },
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
    };

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   0,
    };

    ctx.engine = axquic_client_initial_engine(callback, &ctx);

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);


    user_conn_t *user_conn = malloc(sizeof(user_conn_t));
    memset(user_conn, 0, sizeof(user_conn_t));


    user_conn->fd = xqc_client_create_socket(user_conn, server_addr, server_port);

    user_conn->engine = ctx.engine;
    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, xqc_client_event_callback, user_conn);

    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);


    xqc_cid_t *cid = axquic_connect(ctx.engine, user_conn, conn_settings, server_addr, server_port, token, token_len,
            session_ticket_data, session_len, tp_data, tp_len, (struct sockaddr *)(&user_conn->peer_addr), user_conn->peer_addrlen );

    memcpy(&user_conn->cid, cid, sizeof(*cid));


    axquic_client_stream_t * client_stream = axquic_open_stream(ctx.engine, &user_conn->cid);


    char buf[1024];
    int fin = 0;
    int ret =  axquic_send(client_stream, buf, sizeof(buf), 0);
    ret = axquic_send(client_stream, buf, sizeof(buf), 1);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}

