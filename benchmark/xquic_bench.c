#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include "include/xquic.h"
#include "include/xquic_typedef.h"


//#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

//#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);
#define DEBUG ;

#define TEST_DROP (g_drop_rate != 0 && rand() % 1000 < g_drop_rate)

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_TOKEN_LEN 32

#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_SHORT_HEADER_PACKET_B "\x80\xAB\x3f\x12\x0a\xcd\xef\x00\x89"


typedef struct user_conn_s user_conn_t;

typedef struct user_stats{
    uint64_t        conc_conn_count;
    uint64_t        conc_stream_count;

    uint64_t        send_bytes_count;
    uint64_t        recv_bytes_count;
    uint64_t        send_request_count;
    uint64_t        recv_respont_count;
}user_stats_t;


typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    user_conn_t        *user_conn;
    xqc_http_headers_t http_header;
    char               *send_body;
    size_t              send_body_len;
    uint64_t            send_offset;

    int                 header_sent;

    int                 header_recvd;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
    int                 recv_fin;
    xqc_msec_t          start_time;
} user_stream_t;

typedef struct client_ctx_s {
    xqc_engine_t    *engine;
    struct event    *ev_engine;
    struct event_base *eb;
    int             log_fd;
    int         no_crypto_flag;
    int         congestion;

    struct event    *ev_conc;
    int         cur_conn_num;
} client_ctx_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr_in6  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in6  peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    int                 h3;
    client_ctx_t        *ctx;

    int                 cur_stream_num;
} user_conn_t;


//client_ctx_t ctx;
//struct event_base *eb;
#define MAX_CONN_NUM 1000
int g_use_1rtt = 0;
int g_pacing_on = 0;
int g_conn_num = 100;
int g_stream_num_per_conn = 10;
int g_qpack_header_num = 10;
int g_test_conc = 0;
int g_test_new_create = 1;

#define MAX_HEAD_BUF_LEN 8096
#define MAX_HEADER_COUNT 128
static char g_header_buffer[MAX_HEAD_BUF_LEN];
xqc_http_header_t g_header_array[MAX_HEADER_COUNT];
int g_header_array_read_count = 0;
user_stats_t g_user_stats;


int g_req_cnt;
int g_req_max;
int g_send_body_size;
int g_send_body_size_defined;
int g_save_body;
int g_read_body;
int g_echo_check;
int g_drop_rate;
int g_spec_url;
int g_is_get;
int g_test_case;
int g_ipv6;
char g_write_file[64];
char g_read_file[64];
char g_host[64] = "test.xquic.com";
char g_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[256];

int benchmark_run(client_ctx_t *ctx , int conn_num);

static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}

void xqc_client_set_event_timer(void *user_data, xqc_msec_t wake_after)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

int save_session_cb( char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    //printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _session_cb error\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}


int save_tp_cb(char * data, size_t data_len, void * user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    //printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _tp_cb error\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

void xqc_client_save_token(void *user_data, const unsigned char *token, unsigned token_len)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
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
    //printf("read token size %zu\n", n);
    close(fd);
    return n;
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

int g_send_total = 0;
ssize_t xqc_client_write_socket(void *user, unsigned char *buf, size_t size,
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res;
    int fd = user_conn->fd;
    //printf("xqc_client_write_socket size=%zd, now=%llu, send_total=%d\n",size, now(), ++g_send_total);
    do {
        errno = 0;
        //res = write(fd, buf, size);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        //printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
        }
        if(res > 0){
            g_user_stats.send_bytes_count += res;
        }
    } while ((res < 0) && (errno == EINTR));
    /*socklen_t tmp = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&user_conn->local_addr, &tmp);*/
    return res;
}

int g_ipv6 = 0;

static int xqc_client_create_socket(user_conn_t *user_conn, const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    user_conn->peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    struct sockaddr *saddr = (struct sockaddr *)&user_conn->peer_addr;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    int size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    if (type == AF_INET6) {
        memset(saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)saddr;
        inet_pton(type, addr, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
    } else {
        memset(saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
        inet_pton(type, addr, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
    }


    return fd;

  err:
    close(fd);
    return -1;
}

int xqc_client_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    return 0;
}

int xqc_client_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    event_del(user_conn->ev_socket);

    client_ctx_t * ctx = user_conn->ctx;
    ctx->cur_conn_num--;
    g_user_stats.conc_conn_count--;
    printf("---------------------connection close:%p, cur_conn_num:%d\n", user_conn, ctx->cur_conn_num);
    free(user_conn);

    return 0;
}

void xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

}

int xqc_client_h3_conn_create_notify(xqc_h3_conn_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    return 0;
}

int check_close_user_conn(user_conn_t * user_conn){

    if(user_conn->cur_stream_num > 0){
        return 0;
    }

    if(user_conn->cur_stream_num < 0){
        printf("error cur_stream_num little than 0\n");
        return -1;
    }

    client_ctx_t *ctx = user_conn->ctx;

    event_del(user_conn->ev_socket);
    printf("xqc_conn_close :%p, total conn:%d\n", user_conn, ctx->cur_conn_num);
    int rc = xqc_conn_close(ctx->engine, &user_conn->cid);
    if(rc){

        printf("xqc_conn_close error\n");
        return 0;
    }
    return 0;

}

int xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn errno:%d\n", xqc_h3_conn_get_errno(conn));

    client_ctx_t * ctx = user_conn->ctx;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u\n", stats.send_count, stats.lost_count, stats.tlp_count);

    event_del(user_conn->ev_socket);

    //client_ctx_t * ctx = user_conn->ctx;
    ctx->cur_conn_num--;
    printf("---------------------connection close:%p, cur_conn_num:%d\n", user_conn, ctx->cur_conn_num);

    free(user_conn);
    xqc_h3_conn_set_user_data(conn, NULL);
    return 0;
}

void xqc_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

}

int xqc_client_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    unsigned buff_size = 1024;
    char *buff = malloc(buff_size);
    if (user_stream->send_offset < buff_size) {
        ret = xqc_stream_send(stream, buff + user_stream->send_offset, buff_size - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%lld\n", (long long int)user_stream->send_offset);
        }
    }
    return 0;
}


int xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_client_stream_send(stream, user_stream);
    return ret;
}

int xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    char buff[1000] = {0};
    size_t buff_size = 1000;

    ssize_t read;
    unsigned char fin;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        printf("xqc_stream_recv %zd, fin:%d\n", read, (int)fin);
    } while (read > 0 && !fin);

    return 0;
}

int xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream);
    return 0;
}

static char g_test_header[1024*16] = {0};
xqc_http_header_t g_array_literial_header[] = {
    {
        .name   = {.iov_base = "literial_method", .iov_len = sizeof("literial_method") - 1},
        .value  = {.iov_base = "literial_post", .iov_len = sizeof("literial_post") - 1},
        .flags  = 0,
    },
    {
        .name   = {.iov_base = "literial_content-type", .iov_len = sizeof("literial_content-type") - 1},
        .value  = {.iov_base = "literial_text/plain", .iov_len = sizeof("literial_text/plain") - 1},
        .flags  = 1,
    },
    {
        .name   = {.iov_base = "literial_long", .iov_len = sizeof("literial_long") - 1},
        .value  = {.iov_base = g_test_header, .iov_len = 4096},
        .flags  = 0,

    },
};

xqc_http_header_t g_array_refresh_header[] = {
    {
        .name   = {.iov_base = "refresh_test1", .iov_len = sizeof("refresh_test1") - 1},
        .value  = {.iov_base = g_test_header, .iov_len = 1024},
        .flags  = 0,

    },
    {
        .name   = {.iov_base = "refresh_test2", .iov_len = sizeof("refresh_test2") -1 },
        .value  = {.iov_base = g_test_header, .iov_len = 2048},
        .flags  = 0,
    },
    {
        .name   = {.iov_base = "refresh_test3", .iov_len = sizeof("refresh_test3") - 1},
        .value  = {.iov_base = g_test_header, .iov_len = 1024},
        .flags  = 0,
    },
#if 0
    {
        .name   = {.iov_base = "refresh_test4", .iov_len = sizeof("refresh_test4") - 1},
        .value  = {.iov_base = g_test_header, .iov_len = 1024},
        .flags  = 0,

    },
#endif

};

int xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    ssize_t ret = 0;
    int header_only = 0;
    if(user_stream->send_body_len == 0){
        header_only = 1;
    }
    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &user_stream->http_header, header_only);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
        } else {
            //printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }
    }

    if (header_only) {
        g_user_stats.send_request_count++;
        return 0;
    }

    int fin = 1; //request send fin
    while(user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;
        } else if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return ret;
        } else if(ret == 0){
            break;
        }else {
            user_stream->send_offset += ret;
            //printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }

    if(user_stream->send_offset == user_stream->send_body_len){
        g_user_stats.send_request_count++;
    }
    return 0;
}

int xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_client_request_send(h3_request, user_stream);
    return ret;
}


int xqc_client_request_read_notify(xqc_h3_request_t *h3_request, void *user_data, xqc_request_notify_flag_t flag)
{
    DEBUG;
    int ret;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    //need finish
    return 0;
}

int xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;

    user_conn_t * user_conn = user_stream->user_conn;
    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    //printf("send_body_size:%zu, recv_body_size:%zu\n", stats.send_body_size, stats.recv_body_size);

    if(user_stream->http_header.headers){
        free(user_stream->http_header.headers);
        user_stream->http_header.headers = NULL;
    }

    free(user_stream);

    user_conn->cur_stream_num--;
    g_user_stats.conc_stream_count--;
    check_close_user_conn(user_conn);

    return 0;
}

void
xqc_client_write_handler(user_conn_t *user_conn)
{
    xqc_conn_continue_send(user_conn->ctx->engine, &user_conn->cid);
}


void
xqc_client_read_handler(user_conn_t *user_conn)
{
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    user_conn->peer_addrlen = sizeof(user_conn->peer_addr);

    client_ctx_t *ctx = user_conn->ctx;
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
        if(recv_size > 0){
            g_user_stats.recv_bytes_count += recv_size;
        }
        uint64_t recv_time = now();
        //printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n", recv_size, recv_time);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

        if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&user_conn->local_addr), user_conn->local_addrlen,
                                      (struct sockaddr *) (&user_conn->peer_addr), user_conn->peer_addrlen,
                                      (xqc_msec_t) recv_time, user_conn) != 0) {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);
    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_socket_event_callback(int fd, short what, void *arg)
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
    //printf("xqc_client_timer_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void xqc_client_concurrent_callback(int fd, short what, void *arg){

    client_ctx_t *ctx = (client_ctx_t *)arg;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    if(g_test_conc){
        if(ctx->cur_conn_num < g_conn_num){
            if(benchmark_run(ctx, g_conn_num - ctx->cur_conn_num ) < 0){
                printf("create connection failed\n");
            }
        }
    }else if(g_test_new_create){
        printf("******** calltime:%lu", now());
        if(ctx->cur_conn_num >= MAX_CONN_NUM){
            printf("******* current conn num:%d, max conn num:%d\n", ctx->cur_conn_num, MAX_CONN_NUM);
        }else{
            if(benchmark_run(ctx, g_conn_num) < 0){
                printf("create connection failed1\n");
            }
        }

    }
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    //printf("xqc_client_timeout_callback now %llu\n", now());
    user_conn_t *user_conn = (user_conn_t *) arg;
    client_ctx_t *ctx = user_conn->ctx;
    int rc;
    return;//暂时不自动退出,等待无数据超时退出，后期改成无stream后连接关闭退出
    event_del(user_conn->ev_socket);
    rc = xqc_conn_close(ctx->engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }

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
    //printf("%s",(char*)buf);
    return write(ctx->log_fd, buf, count);
}

user_stream_t * create_user_stream(xqc_engine_t * engine, user_conn_t *user_conn, xqc_cid_t * cid){
    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
    if(user_stream == NULL){
        return NULL;
    }
    if (user_conn->h3) {
        user_stream->h3_request = xqc_h3_request_create(engine, cid, user_stream);
        if (user_stream->h3_request == NULL) {
            return NULL;
        }
    } else {
        user_stream->stream = xqc_stream_create(engine, cid, user_stream);
        if (user_stream->stream == NULL) {
            return NULL;
        }
    }
    user_stream->user_conn = user_conn;
    return user_stream;

}

void client_context_free(client_ctx_t * ctx){

    if(ctx){
        free(ctx);
    }
    return;
}

client_ctx_t * client_create_context_new(){

    client_ctx_t * ctx = malloc(sizeof(client_ctx_t));
    memset(ctx, 0, sizeof(client_ctx_t));


    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0 ,sizeof(engine_ssl_config));
    /* private_key_file cert_file 客户端不用填 */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t callback = {
            /* HTTP3不用设置这个回调 */
            .conn_callbacks = {
                    .conn_create_notify = xqc_client_conn_create_notify,
                    .conn_close_notify = xqc_client_conn_close_notify,
                    .conn_handshake_finished = xqc_client_conn_handshake_finished,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = xqc_client_h3_conn_create_notify, /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
                    .h3_conn_close_notify = xqc_client_h3_conn_close_notify, /* 连接关闭时回调,用户可以回收资源 */
                    .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished, /* 握手完成时回调 */
            },
            /* 仅使用传输层时实现 */
            .stream_callbacks = {
                    .stream_write_notify = xqc_client_stream_write_notify, /* 可写时回调，用户可以继续调用写接口 */
                    .stream_read_notify = xqc_client_stream_read_notify, /* 可读时回调，用户可以继续调用读接口 */
                    .stream_close_notify = xqc_client_stream_close_notify, /* 关闭时回调，用户可以回收资源 */
            },
            /* 使用应用层时实现 */
            .h3_request_callbacks = {
                    .h3_request_write_notify = xqc_client_request_write_notify, /* 可写时回调，用户可以继续调用写接口 */
                    .h3_request_read_notify = xqc_client_request_read_notify, /* 可读时回调，用户可以继续调用读接口 */
                    .h3_request_close_notify = xqc_client_request_close_notify, /* 关闭时回调，用户可以回收资源 */
            },
            .write_socket = xqc_client_write_socket, /* 用户实现socket写接口 */
            .set_event_timer = xqc_client_set_event_timer, /* 设置定时器，定时器到期时调用xqc_engine_main_logic */
            .save_token = xqc_client_save_token, /* 保存token到本地，connect时带上 */
            .log_callbacks = {
                    .log_level = XQC_LOG_ERROR,
                    //.log_level = XQC_LOG_INFO,
                    .xqc_open_log_file = xqc_client_open_log_file,
                    .xqc_close_log_file = xqc_client_close_log_file,
                    .xqc_write_log_file = xqc_client_write_log_file,
            },
            .save_session_cb = save_session_cb,
            .save_tp_cb = save_tp_cb,
    };


    ctx->eb = event_base_new();

    if(ctx->eb == NULL){
        return NULL;
    }
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_client_engine_callback, ctx);
    if(ctx->ev_engine == NULL){
        return NULL;
    }
    ctx->ev_conc = event_new(ctx->eb, -1, 0, xqc_client_concurrent_callback, ctx);
    if(ctx->ev_conc == NULL){
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, ctx);

    if(ctx->engine == NULL){
        return NULL;
    }
    return ctx;


}


//no need ?
#if 0
int client_close_stream(user_stream_t *user_stream){

    int fin = 1;
    ssize_t send_success = xqc_stream_send(user_stream->stream, NULL, 0, fin);

    if (send_success == 1) {
        return 0;
    }

    if (send_success == -XQC_EAGAIN) {
        return -EAGAIN;
    }

    return send_success;

}
#endif


user_conn_t * client_create_connection(client_ctx_t * ctx){
    xqc_engine_t * engine = ctx->engine;
    user_conn_t *user_conn = malloc(sizeof(user_conn_t));
    memset(user_conn, 0, sizeof(user_conn_t));

    //是否使用http3
    user_conn->h3 = 1;
    user_conn->ctx = ctx;

    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* 设置连接超时 */
    struct timeval tv;
    tv.tv_sec = 120;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    user_conn->fd = xqc_client_create_socket(user_conn, TEST_SERVER_ADDR, TEST_SERVER_PORT);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST, xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);
    if (token_len < 0) {
        token_len = 0;
        //user_conn->token = token;
        //user_conn->token_len = token_len;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0 ,sizeof(conn_ssl_config));

    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if (session_len < 0 || tp_len < 0 || g_use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;
    } else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }

    xqc_cong_ctrl_callback_t cong_ctrl = xqc_bbr_cb;

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   g_pacing_on,
            .cong_ctrl_callback = cong_ctrl,
            .ping_on    =   0,
    };

    int no_crypto_flag = 0;
    xqc_cid_t *cid;
    if (user_conn->h3) {
        cid = xqc_h3_connect(engine, user_conn, conn_settings, token, token_len, "127.0.0.1", no_crypto_flag,
                          &conn_ssl_config, (struct sockaddr*)&user_conn->peer_addr, user_conn->peer_addrlen);
    } else {
        cid = xqc_connect(engine, user_conn, conn_settings, token, token_len, "127.0.0.1", no_crypto_flag,
                          &conn_ssl_config, (struct sockaddr*)&user_conn->peer_addr, user_conn->peer_addrlen);
    }


    if(cid == NULL){
        return NULL;
    }

    memcpy(&user_conn->cid, cid, sizeof(*cid));

    return user_conn;

}


#if 0
user_stream * client_open_stream(user_conn_t * user_conn){

    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));

    if (user_conn->h3) {
        user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid, user_stream);
        if(user_stream->h3_request == NULL){
            return NULL;
        }
        xqc_client_request_send(user_stream->h3_request, user_stream);
    }else{
        user_stream->stream = xqc_stream_create(ctx.engine, cid, user_stream);
        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            continue;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);


    }

    return user_stream;

}
#endif

int client_close_stream(user_stream_t * user_stream){

    //主动关闭stream待finish
    return 0;

}

xqc_http_header_t g_headers[] = {
    {
        .name   = {.iov_base = "literial_method_test_insert", .iov_len = sizeof("literial_method_test_insert") - 1},
        .value  = {.iov_base = "literial_post_test_insert", .iov_len = sizeof("literial_post_test_insert") - 1},
        .flags  = 0,
    },
};


//return numbers of header read from file
int client_read_http_headers_from_file(xqc_http_header_t * header_array, int max_header_num, char * file_path){

#if 0
    int header_count = 0;
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(file_path, "r");
    if(fp == NULL){
        return header_count;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if(header_count == 0){

        }

    }
#endif

    int read_len = read_file_data(g_header_buffer, sizeof(g_header_buffer) - 1, file_path);
    if(read_len < 0){

        return 0;
    }

    g_header_buffer[read_len] = '\0';

    int header_count = 0;
    char * p = g_header_buffer;

    while(*p != '\0'){
        char * start_p = p;
        char *end_p = strchr(p, '\n');

        if(end_p == NULL){
            break;
        }
        *end_p = '\0';

        if(header_count == 0){
            char *split_p = strchr(p, ' ');
            if(split_p == NULL){
                printf("error http header file line:%s\n", p);
            }else{
                header_array[header_count].name.iov_base = p;
                header_array[header_count].name.iov_len = split_p - p;
                header_array[header_count].value.iov_base = split_p + 1;
                header_array[header_count].value.iov_len = strlen(split_p + 1);
                header_array[header_count].flags = 0;
                if(header_array[header_count].name.iov_len == 0 || header_array[header_count].value.iov_len == 0){
                    printf("error http header file line:%s\n", p);
                }else{
                    header_count++;
                    if(header_count >= max_header_num){
                        break;
                    }
                }
            }
        }else{
            char *split_p = strchr(p, ':');

            if(split_p == NULL){
                if(*p != '\0'){
                    printf("error http header file line:%s\n", p);
                }
            }else{
                header_array[header_count].name.iov_base = p;
                header_array[header_count].name.iov_len = split_p - p;
                header_array[header_count].value.iov_base = split_p + 1;
                header_array[header_count].value.iov_len = strlen(split_p + 1);
                header_array[header_count].flags = 0;
                if(header_array[header_count].name.iov_len == 0 || header_array[header_count].value.iov_len == 0){
                    printf("error http header file line:%s\n", p);
                }else{
                    header_count++;
                    if(header_count >= max_header_num){
                        break;
                    }
                }
            }
        }

        *end_p = '\n';
        p = end_p;
        p++;
    }
    return header_count;
}

#define MAX_QPACK_KEY_LEN 128
#define MAX_QPACK_VALUE_LEN 4096
#define HTTP_BODY_MAX_SIZE 1024*1024
char g_client_body[HTTP_BODY_MAX_SIZE];
char g_qpack_key[MAX_QPACK_KEY_LEN];
char g_qpack_value[MAX_QPACK_VALUE_LEN];

int client_prepare_http_header(user_stream_t * user_stream){
    xqc_http_header_t * headers = malloc(g_qpack_header_num * sizeof(xqc_http_header_t)); //需要释放

    if(headers==NULL){
        return -1;
    }
    int i = 0;
    if(g_qpack_header_num <= g_header_array_read_count){
        for(i = 0; i < g_qpack_header_num; i++){
            xqc_http_header_t *hd = headers+i;
            hd->name.iov_base = g_header_array[i].name.iov_base;
            hd->name.iov_len = g_header_array[i].name.iov_len;
            hd->value.iov_base = g_header_array[i].value.iov_base;
            hd->value.iov_len = g_header_array[i].value.iov_len;
            hd->flags = g_header_array[i].flags;
        }
    }else{
        for(i = 0; i < g_header_array_read_count; i++){
            xqc_http_header_t *hd = headers+i;
            hd->name.iov_base = g_header_array[i].name.iov_base;
            hd->name.iov_len = g_header_array[i].name.iov_len;
            hd->value.iov_base = g_header_array[i].value.iov_base;
            hd->value.iov_len = g_header_array[i].value.iov_len;
            hd->flags = g_header_array[i].flags;
        }


        for(i = g_header_array_read_count; i < g_qpack_header_num; i++){
            xqc_http_header_t *hd = headers+i;
            int m = 0, n = 0;
            m = rand();
            n = rand();
            hd->name.iov_base = g_qpack_key;
            hd->name.iov_len = m%(128 - 1) + 1;

            hd->value.iov_base = g_qpack_value;
            hd->value.iov_len = n%(4095-1) + 1;
            hd->flags = 0;
        }
    }

    user_stream->http_header.headers = headers;
    user_stream->http_header.count = g_qpack_header_num;

    return 0;

}

int client_prepare_http_data(user_stream_t * user_stream){

    //user_stream->http_header.headers = g_headers;
    //user_stream->http_header.count = sizeof(g_headers)/sizeof(xqc_http_header_t);
    if(client_prepare_http_header(user_stream) < 0){
        return -1;
    }

    user_stream->send_body = g_client_body;
    user_stream->send_body_len = 2*1024;
    user_stream->send_offset = 0;

    user_stream->header_sent = 0;

    return 0;
}

int benchmark_run(client_ctx_t *ctx, int conn_num){

    int i = 0, j = 0;
    for(i = 0 ; i < conn_num; i++){
        user_conn_t * user_conn = client_create_connection(ctx);

        if(user_conn == NULL){
            printf("error create user conn\n");
            return -1;
        }


        for(j = 0; j < g_stream_num_per_conn; j++){
            user_stream_t * user_stream = create_user_stream(ctx->engine, user_conn, &user_conn->cid);

            if(user_stream == NULL){
                printf("error create user stream\n");
                return -1;
            }

            user_conn->cur_stream_num++;
            g_user_stats.conc_stream_count++;

            client_prepare_http_data(user_stream);

            xqc_client_request_send(user_stream->h3_request, user_stream);

        }
        ctx->cur_conn_num++;
        g_user_stats.conc_conn_count++;
        printf("*****************create connection:%p, cur_conn_num:%d\n", user_conn, ctx->cur_conn_num);
    }

    return 0;
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

    memset(g_qpack_key, 'k', sizeof(g_qpack_key));
    memset(g_qpack_value, 'v', sizeof(g_qpack_value));

    memset(&g_user_stats, 0, sizeof(user_stats_t));

#if 0
    client_ctx_t * ctx = malloc(sizeof(client_ctx_t));
    memset(ctx, 0, sizeof(client_ctx_t));


    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0 ,sizeof(engine_ssl_config));
    /* private_key_file cert_file 客户端不用填 */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t callback = {
            /* HTTP3不用设置这个回调 */
            .conn_callbacks = {
                    .conn_create_notify = xqc_client_conn_create_notify,
                    .conn_close_notify = xqc_client_conn_close_notify,
                    .conn_handshake_finished = xqc_client_conn_handshake_finished,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = xqc_client_h3_conn_create_notify, /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
                    .h3_conn_close_notify = xqc_client_h3_conn_close_notify, /* 连接关闭时回调,用户可以回收资源 */
                    .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished, /* 握手完成时回调 */
            },
            /* 仅使用传输层时实现 */
            .stream_callbacks = {
                    .stream_write_notify = xqc_client_stream_write_notify, /* 可写时回调，用户可以继续调用写接口 */
                    .stream_read_notify = xqc_client_stream_read_notify, /* 可读时回调，用户可以继续调用读接口 */
                    .stream_close_notify = xqc_client_stream_close_notify, /* 关闭时回调，用户可以回收资源 */
            },
            /* 使用应用层时实现 */
            .h3_request_callbacks = {
                    .h3_request_write_notify = xqc_client_request_write_notify, /* 可写时回调，用户可以继续调用写接口 */
                    .h3_request_read_notify = xqc_client_request_read_notify, /* 可读时回调，用户可以继续调用读接口 */
                    .h3_request_close_notify = xqc_client_request_close_notify, /* 关闭时回调，用户可以回收资源 */
            },
            .write_socket = xqc_client_write_socket, /* 用户实现socket写接口 */
            .set_event_timer = xqc_client_set_event_timer, /* 设置定时器，定时器到期时调用xqc_engine_main_logic */
            .save_token = xqc_client_save_token, /* 保存token到本地，connect时带上 */
            .log_callbacks = {
                    .log_level = XQC_LOG_DEBUG,
                    //.log_level = XQC_LOG_INFO,
                    .xqc_open_log_file = xqc_client_open_log_file,
                    .xqc_close_log_file = xqc_client_close_log_file,
                    .xqc_write_log_file = xqc_client_write_log_file,
            },
            .save_session_cb = save_session_cb,
            .save_tp_cb = save_tp_cb,
    };


    ctx->eb = event_base_new();

    if(ctx->eb == NULL){
        return 0;
    }
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_client_engine_callback, ctx);
    if(ctx->ev_engine == NULL){
        return 0;
    }

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, ctx);

    if(ctx->engine == NULL){
        return 0;
    }

#endif

    char *header_file = "./http_header_file";
    g_header_array_read_count = client_read_http_headers_from_file(g_header_array, MAX_HEADER_COUNT, header_file);


    client_ctx_t * ctx = NULL;
    ctx = client_create_context_new();
    if(ctx == NULL){
        printf("ctx create error\n");
        exit(0);
    }

    if(benchmark_run(ctx, g_conn_num) < 0){
        printf("***************benchmark_run failed\n");
    }

    event_base_dispatch(ctx->eb);
}
