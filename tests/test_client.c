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
#include "include/xquic.h"
#include "include/xquic_typedef.h"

int printf_null(const char *format, ...)
{
    return 0;
}

//打开注释 不打印printf
//#define printf printf_null

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define TEST_DROP (g_drop_rate != 0 && rand() % 1000 < g_drop_rate)

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_TOKEN_LEN 32

typedef struct user_conn_s user_conn_t;

typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    user_conn_t        *user_conn;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
    int                 recv_fin;
    xqc_msec_t          start_time;
} user_stream_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    int                 h3;
} user_conn_t;

typedef struct client_ctx_s {
    xqc_engine_t    *engine;
    struct event    *ev_engine;
    int             log_fd;
} client_ctx_t;

client_ctx_t ctx;
struct event_base *eb;
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
char g_write_file[64];
char g_read_file[64];
char g_host[64] = "test.xquic.com";
char g_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[256];

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
    printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

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
    printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

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
    printf("read token size %zu\n", n);
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
    ssize_t res = 0;
    int fd = user_conn->fd;
    //printf("xqc_client_write_socket size=%zd, now=%llu, send_total=%d\n",size, now(), ++g_send_total);
    do {
        errno = 0;
        //res = write(fd, buf, size);
        if (TEST_DROP) return size;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        //printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
        }
    } while ((res < 0) && (errno == EINTR));
    /*socklen_t tmp = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&user_conn->local_addr, &tmp);*/
    return res;
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

    int size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    memset(saddr, 0, sizeof(struct sockaddr_in));

    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);
    saddr->sin_addr = *((struct in_addr *)remote->h_addr);

#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }
#endif
    /*socklen_t tmp = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&user_conn->local_addr, &tmp);

    printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
    printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

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
    free(user_conn);
    event_base_loopbreak(eb);
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

int xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn errno:%d\n", xqc_h3_conn_get_errno(conn));

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, early_data_flag:%d\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.early_data_flag);

    free(user_conn);
    event_base_loopbreak(eb);
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

    unsigned buff_size = 1000*1024;
    user_stream->send_body = malloc(buff_size);
    if (user_stream->send_offset < buff_size) {
        ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, buff_size - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_stream_send error %d\n", ret);
            return ret;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%lld\n", user_stream->send_offset);
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
        printf("xqc_stream_recv %lld, fin:%d\n", read, fin);
        if (read < 0) {
            return read;
        }
    } while (read > 0 && !fin);

    return 0;
}

int xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream);
    return 0;
}

int xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    if (user_stream->start_time == 0) {
        user_stream->start_time = now();
    }
    ssize_t ret = 0;
    xqc_http_header_t header[] = {
            {
                    .name   = {.iov_base = ":method", .iov_len = 7},
                    .value  = {.iov_base = "POST", .iov_len = 4},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = ":scheme", .iov_len = 7},
                    .value  = {.iov_base = g_scheme, .iov_len = strlen(g_scheme)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = "host", .iov_len = 4},
                    .value  = {.iov_base = g_host, .iov_len = strlen(g_host)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = ":path", .iov_len = 5},
                    .value  = {.iov_base = g_path, .iov_len = strlen(g_path)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = "content-type", .iov_len = 12},
                    .value  = {.iov_base = "text/plain", .iov_len = 10},
                    .flags  = 0,
            },
            /*{
                    .name   = {.iov_base = "content-length", .iov_len = 14},
                    .value  = {.iov_base = "512", .iov_len = 3},
                    .flags  = 0,
            },*/
            /*{
                    .name   = {.iov_base = ":status", .iov_len = 7},
                    .value  = {.iov_base = "200", .iov_len = 3},
                    .flags  = 0,
            },*/
            /*{
                    .name   = {.iov_base = "1234567890123456789012345678901234567890", .iov_len = 40},
                    .value  = {.iov_base = "1234567890123456789012345678901234567890", .iov_len = 40},
                    .flags  = 0,
            },*/
    };
    xqc_http_headers_t headers = {
            .headers = header,
            .count  = sizeof(header) / sizeof(header[0]),
    };

    int header_only = g_is_get;
    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (header_only) {
            return 0;
        }
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (g_read_body) {
            user_stream->send_body = malloc(user_stream->send_body_max);
        } else {
            user_stream->send_body = malloc(g_send_body_size);
            memset(user_stream->send_body, 1, g_send_body_size);
        }
        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        /* 指定大小 > 指定文件 > 默认大小 */
        if (g_send_body_size_defined) {
            user_stream->send_body_len = g_send_body_size;
        } else if (g_read_body) {
            ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
            if (ret < 0) {
                printf("read body error\n");
                return -1;
            } else {
                user_stream->send_body_len = ret;
            }
        } else {
            user_stream->send_body_len = g_send_body_size;
        }
    }

    int fin = 1;
    if (g_test_case == 4) { //test fin_only
        fin = 0;
    }
    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;
        } else if (ret < 0) {
            printf("xqc_h3_request_send_body error %d\n", ret);
            return ret;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%lld\n", ret, user_stream->send_offset);
        }
    }
    if (g_test_case == 4) { //test fin_only
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_h3_request_send_body sent:%zd, offset=%lld, fin=1\n", ret, user_stream->send_offset);
        }
    }
    return 0;
}

int xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    if (g_test_case == 1) {
        xqc_h3_request_close(h3_request);
        return 0;
    }
    if (g_test_case == 2) {
        xqc_h3_conn_close(ctx.engine, &user_stream->user_conn->cid);
        return 0;
    }
    if (g_test_case == 3) {
        return -1;
    }
    ret = xqc_client_request_send(h3_request, user_stream);
    return ret;
}

int xqc_client_request_read_notify(xqc_h3_request_t *h3_request, void *user_data, xqc_request_notify_flag_t flag)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }
        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n",headers->headers[i].name.iov_base, headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd = 1;

        if (fin) {
            /* 只有header，请求接收完成，处理业务逻辑 */
            user_stream->recv_fin = 1;
            return 0;
        }
        //继续收body
    }

    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return 0;
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    if (g_echo_check && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(user_stream->send_body_len);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    ssize_t read;
    ssize_t read_sum = 0;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        if (read < 0) {
            printf("xqc_h3_request_recv_body error %lld\n", read);
            return read;
        }

        if(save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if(save) fflush(user_stream->recv_body_fp);

        /* 保存接收到的body到内存 */
        if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        //printf("xqc_h3_request_recv_body %lld, fin:%d\n", read, fin);
        read_sum += read;
        user_stream->recv_body_len += read;

    } while (read > 0 && !fin);

    printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_msec_t now_us = now();
        printf("\033[33m>>>>>>>> request time cost:%lld us, speed:%lld K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size)*1000/(now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size);
    }
    return 0;
}

int xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;
    user_conn_t *user_conn = user_stream->user_conn;

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu, recv_fin:%d\n", stats.send_body_size, stats.recv_body_size, user_stream->recv_fin);

    if (g_echo_check) {
        int pass = 0;
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
            pass = 1;
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    if (g_req_cnt < g_req_max) {
        user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        user_stream->h3_request = xqc_h3_request_create(ctx.engine, &user_conn->cid, user_stream);
        g_req_cnt++;
    }
    return 0;
}

void
xqc_client_socket_write_handler(user_conn_t *user_conn)
{
    DEBUG
    xqc_conn_continue_send(ctx.engine, &user_conn->cid);
}


void
xqc_client_socket_read_handler(user_conn_t *user_conn)
{
    //DEBUG;

    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    user_conn->peer_addrlen = sizeof(user_conn->peer_addr);

    do {
        recv_size = recvfrom(user_conn->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &user_conn->peer_addr,
                             &user_conn->peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(errno));
            break;
        }
        recv_sum += recv_size;

        if (user_conn->local_addrlen == 0) {
            socklen_t tmp = sizeof(struct sockaddr_in);
            getsockname(user_conn->fd, (struct sockaddr *) &user_conn->local_addr, &tmp);
            user_conn->local_addrlen = sizeof(struct sockaddr_in);
        }

        uint64_t recv_time = now();
        //printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n", recv_size, recv_time);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

        if (TEST_DROP) continue;
        if (xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&user_conn->local_addr), user_conn->local_addrlen,
                                      (struct sockaddr *) (&user_conn->peer_addr), user_conn->peer_addrlen,
                                      (xqc_msec_t) recv_time, user_conn) != 0) {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);

    printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx.engine);
}


static void
xqc_client_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        xqc_client_socket_write_handler(user_conn);
    } else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_conn);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}


static void
xqc_client_engine_callback(int fd, short what, void *arg)
{
    printf("timer wakeup now:%llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timeout_callback now %llu\n", now());
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    rc = xqc_conn_close(ctx.engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }

    //event_base_loopbreak(eb);
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

void usage(int argc, char *argv[]) {
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [Options]\n"
"\n"
"Options:\n"
"   -a    Server addr.\n"
"   -p    Server port.\n"
"   -P    Number of Parallel requests per single connection. Default 1.\n"
"   -n    Total number of requests to send. Defaults 1.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic\n"
"   -C    Pacing on.\n"
"   -t    Connection timeout. Default 3 seconds.\n"
"   -T    Transport layer. No HTTP3.\n"
"   -1    Force 1RTT.\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -E    Echo check on. Compare sent data with received data.\n"
"   -d    Drop rate ‰.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -G    GET on. Default is POST\n"
"   -x    Test case ID\n"
, prog);
}

int main(int argc, char *argv[]) {

    g_req_cnt = 0;
    g_req_max = 1;
    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_save_body = 0;
    g_read_body = 0;
    g_echo_check = 0;
    g_drop_rate = 0;
    g_spec_url = 0;
    g_is_get = 0;
    g_test_case = 0;

    char server_addr[64] = TEST_SERVER_ADDR;
    int server_port = TEST_SERVER_PORT;
    int req_paral = 1;
    char c_cong_ctl = 'c';
    char c_log_level = 'd';
    int pacing_on = 0;
    int conn_timeout = 3;
    int transport = 0;
    int use_1rtt = 0;

    int ch = 0;
    while((ch = getopt(argc, argv, "a:p:P:n:c:Ct:T1s:w:r:l:Ed:u:Gx:")) != -1){
        switch(ch)
        {
            case 'a':
                printf("option addr:'%s'\n", optarg);
                snprintf(server_addr, sizeof(server_addr), optarg);
                break;
            case 'p':
                printf("option port :%s\n", optarg);
                server_port = atoi(optarg);
                break;
            case 'P': //请求并发数
                printf("option req_paral :%s\n", optarg);
                req_paral = atoi(optarg);
                break;
            case 'n': //请求总数
                printf("option req_max :%s\n", optarg);
                g_req_max = atoi(optarg);
                break;
            case 'c': //拥塞算法 r:reno b:bbr c:cubic
                printf("option cong_ctl :%s\n", optarg);
                c_cong_ctl = optarg[0];
                break;
            case 'C': //pacing on
                printf("option pacing :%s\n", "on");
                pacing_on = 1;
                break;
            case 't': //n秒后关闭连接
                printf("option conn_timeout :%s\n", optarg);
                conn_timeout = atoi(optarg);
                break;
            case 'T': //仅使用传输层，不使用HTTP3
                printf("option transport :%s\n", "on");
                transport = 1;
                break;
            case '1': //强制走1RTT
                printf("option 1RTT :%s\n", "on");
                use_1rtt = 1;
                break;
            case 's': //指定发送body字节数
                printf("option send_body_size :%s\n", optarg);
                g_send_body_size = atoi(optarg);
                g_send_body_size_defined = 1;
                if (g_send_body_size > MAX_BUF_SIZE) {
                    printf("max send_body_size :%d\n", MAX_BUF_SIZE);
                    exit(0);
                }
                break;
            case 'w': //保存接收body到文件
                printf("option save body :%s\n", optarg);
                snprintf(g_write_file, sizeof(g_write_file), optarg);
                g_save_body = 1;
                break;
            case 'r': //读取文件当body，优先级 s > r
                printf("option read body :%s\n", optarg);
                snprintf(g_read_file, sizeof(g_read_file), optarg);
                g_read_body = 1;
                break;
            case 'l': //log level. e:error d:debug.
                printf("option log level :%s\n", optarg);
                c_log_level = optarg[0];
                break;
            case 'E': //校验服务端echo数据
                printf("option echo check :%s\n", "on");
                g_echo_check = 1;
                break;
            case 'd': //丢包率 ‰
                printf("option drop rate :%s\n", optarg);
                g_drop_rate = atoi(optarg);
                srand((unsigned)time(NULL));
                break;
            case 'u': //请求url
                printf("option url :%s\n", optarg);
                snprintf(g_url, sizeof(g_url), optarg);
                g_spec_url = 1;
                sscanf(g_url,"%[^://]://%[^/]%[^?]", g_scheme, g_host, g_path);
                //printf("%s-%s-%s\n",g_scheme, g_host, g_path);
                break;
            case 'G': //Get请求
                printf("option get :%s\n", "on");
                g_is_get = 1;
                break;
            case 'x': //test case id
                printf("option test case id:'%s'\n", optarg);
                g_test_case = atoi(optarg);
                break;
            default:
                printf("other option :%c\n", ch);
                usage(argc, argv);
                exit(0);
        }

    }


    memset(&ctx, 0, sizeof(ctx));


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
                    .log_level = c_log_level == 'e' ? XQC_LOG_ERROR : XQC_LOG_DEBUG,
                    //.log_level = XQC_LOG_INFO,
                    .xqc_open_log_file = xqc_client_open_log_file,
                    .xqc_close_log_file = xqc_client_close_log_file,
                    .xqc_write_log_file = xqc_client_write_log_file,
            },
            .save_session_cb = save_session_cb,
            .save_tp_cb = save_tp_cb,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
    } else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    } else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    } else {
        printf("unknown cong_ctrl, option is b, r, c\n");
        return -1;
    }

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   pacing_on,
            .cong_ctrl_callback = cong_ctrl,
            .ping_on    =   0,
    };

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, &ctx);

    user_conn_t *user_conn;
    user_conn = calloc(1, sizeof(user_conn_t));

    //是否使用http3
    user_conn->h3 = transport ? 0 : 1;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* 设置连接超时 */
    struct timeval tv;
    tv.tv_sec = conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    user_conn->fd = xqc_client_create_socket(user_conn, server_addr, server_port);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);
    if (token_len > 0) {
        user_conn->token = token;
        user_conn->token_len = token_len;
    }


    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0 ,sizeof(conn_ssl_config));

    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;
    } else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }


    xqc_cid_t *cid;
    if (user_conn->h3) {
        cid = xqc_h3_connect(ctx.engine, user_conn, conn_settings, user_conn->token, user_conn->token_len, "127.0.0.1", 0,
                          &conn_ssl_config, (struct sockaddr*)&user_conn->peer_addr, user_conn->peer_addrlen);
    } else {
        cid = xqc_connect(ctx.engine, user_conn, conn_settings, user_conn->token, user_conn->token_len, "127.0.0.1", 0,
                          &conn_ssl_config, (struct sockaddr*)&user_conn->peer_addr, user_conn->peer_addrlen);
    }
    if (cid == NULL) {
        printf("xqc_connect error\n");
        return 0;
    }
    /* cid要copy到自己的内存空间，防止内部cid被释放导致crash */
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    for (int i = 0; i < req_paral; i++) {
        g_req_cnt++;
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        if (user_conn->h3) {
            user_stream->h3_request = xqc_h3_request_create(ctx.engine, cid, user_stream);
            if (user_stream->h3_request == NULL) {
                printf("xqc_h3_request_create error\n");
                continue;
            }
            xqc_client_request_send(user_stream->h3_request, user_stream);
            //xqc_h3_request_close(user_stream->h3_request);
        } else {
            user_stream->stream = xqc_stream_create(ctx.engine, cid, user_stream);
            if (user_stream->stream == NULL) {
                printf("xqc_stream_create error\n");
                continue;
            }
            xqc_client_stream_send(user_stream->stream, user_stream);
        }
    }
    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
