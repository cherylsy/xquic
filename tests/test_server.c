#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <event2/event.h>
#include <inttypes.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

int printf_null(const char *format, ...)
{
    return 0;
}

//打开注释不打印printf
//#define printf printf_null

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
} user_stream_t;

typedef struct user_conn_s {
    struct event       *ev_timeout;
    struct sockaddr_in6  peer_addr;
    socklen_t           peer_addrlen;
    xqc_cid_t           cid;
} user_conn_t;

typedef struct xqc_server_ctx_s {
    int fd;
    xqc_engine_t        *engine;
    struct sockaddr_in6  local_addr;
    socklen_t           local_addrlen;
    struct event        *ev_socket;
    struct event        *ev_engine;
    int                 log_fd;
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;
int g_echo = 0;
int g_send_body_size;
int g_send_body_size_defined;
int g_save_body;
int g_read_body;
int g_spec_url;
int g_ipv6;
char g_write_file[256];
char g_read_file[256];
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

void xqc_server_set_event_timer(void *user_data, xqc_msec_t wake_after)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

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

int xqc_server_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data) {

    DEBUG;

    return 0;
}

int xqc_server_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data) {

    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    return 0;
}

void xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

}

int xqc_server_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* echo > 指定大小 > 指定文件 > 默认大小 */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;
        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;
                } else {
                    user_stream->send_body_len = ret;
                }
            } else {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return ret;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
        }
    }
    return 0;
}

int xqc_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->stream = stream;
    xqc_stream_set_user_data(stream, user_stream);

    return 0;
}

int xqc_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int xqc_server_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    //DEBUG;

    int ret = xqc_server_stream_send(stream, user_data);

    return ret;
}

int xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (g_echo && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(MAX_BUF_SIZE);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;
    ssize_t read_sum = 0;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return read;
        }
        read_sum += read;

        /* 保存接收到的body到文件 */
        if(save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if (save) fflush(user_stream->recv_body_fp);

        /* 保存接收到的body到内存 */
        if (g_echo) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    if (fin) {
        xqc_server_stream_send(stream, user_data);
    }
    return 0;
}

int xqc_server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, xqc_cid_t *cid, void *user_data) {

    DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)user_data;

    user_conn_t *user_conn = calloc(1, sizeof(*user_conn));
    xqc_h3_conn_set_user_data(h3_conn, user_conn);

    socklen_t peer_addrlen;
    struct sockaddr* peer_addr = xqc_h3_conn_get_peer_addr(h3_conn, &peer_addrlen);
    memcpy(&user_conn->peer_addr, peer_addr, peer_addrlen);
    user_conn->peer_addrlen = peer_addrlen;

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    return 0;
}

int xqc_server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, xqc_cid_t *cid, void *user_data) {

    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    //event_base_loopbreak(eb);
    return 0;
}

void xqc_server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);
}


int xqc_server_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
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
            {
                    .name   = {.iov_base = ":status", .iov_len = 7},
                    .value  = {.iov_base = "200", .iov_len = 3},
                    .flags  = 0,
            },
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

    int header_only = 0;
    if (g_echo && user_stream->recv_body_len == 0) {
        header_only = 1;
    }
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

        /* echo > 指定大小 > 指定文件 > 默认大小 */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;
        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;
                } else {
                    user_stream->send_body_len = ret;
                }
            } else {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return ret;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }
    return 0;
}

int xqc_server_request_create_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;
    xqc_h3_request_set_user_data(h3_request, user_stream);

    return 0;
}

int xqc_server_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int xqc_server_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_server_request_send(h3_request, user_stream);
    return ret;
}

int xqc_server_request_read_notify(xqc_h3_request_t *h3_request, void *user_data, xqc_request_notify_flag_t flag)
{
    //DEBUG;
    int ret;
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
            printf("%s = %s\n",(char*)headers->headers[i].name.iov_base, (char*)headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd = 1;

        if (fin) {
            /* 只有header，请求接收完成，处理业务逻辑 */
            xqc_server_request_send(h3_request, user_stream);
            return 0;
        }

        //继续收body
    }

    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return 0;
    }

    if (g_echo && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(MAX_BUF_SIZE);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;
    ssize_t read_sum = 0;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return read;
        }
        //printf("xqc_h3_request_recv_body %lld, fin:%d\n", read, fin);
        read_sum += read;

        /* 保存接收到的body到文件 */
        if(save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if (save) fflush(user_stream->recv_body_fp);

        /* 保存接收到的body到内存 */
        if (g_echo) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        user_stream->recv_body_len += read;
        /*xqc_h3_request_close(h3_request);
        return 0;*/

    } while (read > 0 && !fin);

    printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    // 打开注释，服务端收到包后测试发送reset
    // h3_request->h3_stream->h3_conn->conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;

    if (fin) {
        xqc_server_request_send(h3_request, user_stream);
    }

    return 0;
}

ssize_t xqc_server_write_socket(void *user_data, unsigned char *buf, size_t size,
                        const struct sockaddr *peer_addr,
                        socklen_t peer_addrlen) {
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data; //user_data可能为空，当发送reset时
    ssize_t res;
    int fd = ctx.fd;
    //printf("xqc_server_send size=%zd now=%llu\n",size, now());
    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        //printf("xqc_server_send write %zd, %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));

    return res;
}


void
xqc_server_socket_write_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
}

int g_recv_total = 0;
void
xqc_server_socket_read_handler(xqc_server_ctx_t *ctx)
{
    //DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
#ifdef __linux__
    int batch = 0; /* 不一定是同一条连接上的包 */
    if (batch) {
#define VLEN 100
#define BUFSIZE XQC_PACKET_TMP_BUF_LEN
#define TIMEOUT 10
        struct sockaddr_in6 pa[VLEN];
        struct mmsghdr msgs[VLEN];
        struct iovec iovecs[VLEN];
        char bufs[VLEN][BUFSIZE+1];
        struct timespec timeout;
        int retval;

        do {
            memset(msgs, 0, sizeof(msgs));
            for (int i = 0; i < VLEN; i++) {
                iovecs[i].iov_base = bufs[i];
                iovecs[i].iov_len = BUFSIZE;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &pa[i];
                msgs[i].msg_hdr.msg_namelen = peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(ctx->fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(ctx->engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                              (struct sockaddr *) (&pa[i]), peer_addrlen, (xqc_msec_t) recv_time,
                                              NULL) != 0) {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    ssize_t recv_size = 0;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    do {
        recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &peer_addr,
                             &peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            //printf("!!!!!!!!!errno EAGAIN\n");
            break;
        }
        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(errno));
            break;
        }
        recv_sum += recv_size;

        uint64_t recv_time = now();
        //printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/
        if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *) (&peer_addr), peer_addrlen, (xqc_msec_t) recv_time,
                                      NULL) != 0) {
            printf("xqc_server_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);

finish_recv:
    printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}


static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx);
    } else if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

int xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = calloc(1, sizeof(*user_conn));
    xqc_conn_set_user_data(conn, user_conn);

    socklen_t peer_addrlen;
    struct sockaddr* peer_addr = xqc_conn_get_peer_addr(conn, &peer_addrlen);
    memcpy(&user_conn->peer_addr, peer_addr, peer_addrlen);
    user_conn->peer_addrlen = peer_addrlen;

    return 0;
}

static int xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;

    int optval;

    fd = socket(type, SOCK_DGRAM, 0);
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
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        addr_v6->sin6_addr = in6addr_any;
    } else {
        memset(saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
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
    //DEBUG;
    printf("timer wakeup now:%"PRIu64"\n", now());
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}


int xqc_server_open_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/slog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
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

void stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
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
"   -p    Server port.\n"
"   -e    Echo. Send received body.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic\n"
"   -C    Pacing on.\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority e > s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -6    IPv6\n"
, prog);
}

int main(int argc, char *argv[]) {

    signal (SIGINT, stop);
    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_save_body = 0;
    g_read_body = 0;
    g_spec_url = 0;
    g_ipv6 = 0;

    int server_port = TEST_PORT;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int pacing_on = 0;

    int ch = 0;
    while((ch = getopt(argc, argv, "p:ec:Cs:w:r:l:u:6")) != -1){
        switch(ch)
        {
            case 'p':
                printf("option port :%s\n", optarg);
                server_port = atoi(optarg);
                break;
            case 'e': //返回接收到的body
                printf("option echo :%s\n", "on");
                g_echo = 1;
                break;
            case 'c': //拥塞算法 r:reno b:bbr c:cubic
                printf("option cong_ctl :%s\n", optarg);
                c_cong_ctl = optarg[0];
                break;
            case 'C': //pacing on
                printf("option pacing :%s\n", "on");
                pacing_on = 1;
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
            case 'r': //读取文件当body，优先级 e > s > r
                printf("option read body :%s\n", optarg);
                snprintf(g_read_file, sizeof(g_read_file), optarg);
                g_read_body = 1;
                break;
            case 'l': //log level. e:error d:debug.
                printf("option log level :%s\n", optarg);
                c_log_level = optarg[0];
                break;
            case 'u': //请求url
                printf("option url :%s\n", optarg);
                snprintf(g_url, sizeof(g_url), optarg);
                g_spec_url = 1;
                sscanf(g_url,"%[^://]://%[^/]%[^?]", g_scheme, g_host, g_path);
                //printf("%s-%s-%s\n",g_scheme, g_host, g_path);
                break;
            case '6': //IPv6
                printf("option IPv6 :%s\n", "on");
                g_ipv6 = 1;
                break;
            default:
                printf("other option :%c\n", ch);
                usage(argc, argv);
                exit(0);
        }

    }

    memset(&ctx, 0, sizeof(ctx));

    char g_session_ticket_file[] = "session_ticket.key";


    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    engine_ssl_config.alpn_list = NULL;
    engine_ssl_config.alpn_list_len = 0;

    char g_session_ticket_key[2048];
    int ticket_key_len  = read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);

    if(ticket_key_len < 0){
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;
    }else{
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_server_conn_create_notify,
                    .conn_close_notify = xqc_server_conn_close_notify,
                    .conn_handshake_finished = xqc_server_conn_handshake_finished,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = xqc_server_h3_conn_create_notify,
                    .h3_conn_close_notify = xqc_server_h3_conn_close_notify,
                    .h3_conn_handshake_finished = xqc_server_h3_conn_handshake_finished,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_server_stream_write_notify,
                    .stream_read_notify = xqc_server_stream_read_notify,
                    .stream_create_notify = xqc_server_stream_create_notify,
                    .stream_close_notify = xqc_server_stream_close_notify,
            },
            .h3_request_callbacks = {
                    .h3_request_write_notify = xqc_server_request_write_notify,
                    .h3_request_read_notify = xqc_server_request_read_notify,
                    .h3_request_create_notify = xqc_server_request_create_notify,
                    .h3_request_close_notify = xqc_server_request_close_notify,
            },
            .write_socket = xqc_server_write_socket,
            .server_accept = xqc_server_accept,
            .set_event_timer = xqc_server_set_event_timer,
            .log_callbacks = {
                    .log_level = c_log_level == 'e' ? XQC_LOG_ERROR : (c_log_level == 'i' ? XQC_LOG_INFO : XQC_LOG_DEBUG),
                    //.log_level = XQC_LOG_INFO,
                    .xqc_open_log_file = xqc_server_open_log_file,
                    .xqc_close_log_file = xqc_server_close_log_file,
                    .xqc_write_log_file = xqc_server_write_log_file,
            },
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
    };
    xqc_server_set_conn_settings(conn_settings);

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &ctx);

    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &engine_ssl_config, callback, &ctx);

    if(ctx.engine == NULL){
        printf("error create engine\n");
        return -1;
    }

    ctx.fd = xqc_server_create_socket(TEST_ADDR, server_port);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_socket = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, &ctx);

    event_add(ctx.ev_socket, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
