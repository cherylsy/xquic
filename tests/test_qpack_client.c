#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include "include/xquic.h"
#include "http3/xqc_h3_frame.h"
#include "http3/xqc_h3_stream.h"
#include "http3/xqc_h3_qpack.h"
#include "http3/xqc_h3_conn.h"
#include "http3/xqc_h3_request.h"
#include "include/xquic_typedef.h"

int printf_null(const char *format, ...)
{
    return 0;
}

//打开注释 不打印printf
//#define printf printf_null

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);


#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500

#define XQC_MAX_TOKEN_LEN 32

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

static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000000 + tv.tv_usec;
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
    printf("read token size %zd\n", n);
    printf("0x%x\n", token[0]);
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
        printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
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

    /*if (connect(fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }*/

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
    printf("send_count:%u, lost_count:%u, tlp_count:%u\n", stats.send_count, stats.lost_count, stats.tlp_count);

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


xqc_http_header_t g_array_draining_header[] = {
    {
        .name   = {.iov_base = "draining_test1", .iov_len = sizeof("draining_test1") - 1},
        .value  = {.iov_base = "draining_value1", .iov_len = sizeof("draining_value1") - 1},
        .flags  = 0,

    },
    {
        .name   = {.iov_base = "draining_test2", .iov_len = sizeof("draining_test2") -1 },
        .value  = {.iov_base = g_test_header, .iov_len = 1024},
        .flags  = 0,
    },
    {
        .name   = {.iov_base = "draining_test3", .iov_len = sizeof("draining_test3") - 1},
        .value  = {.iov_base = g_test_header, .iov_len = 2048},
        .flags  = 0,
    },
    {
        .name   = {.iov_base = "draining_test4", .iov_len = sizeof("draining_test4") -1 },
        .value  = {.iov_base = g_test_header, .iov_len = 512},
        .flags  = 0,
    },

};


xqc_http_header_t g_header = {
    .name   = {.iov_base = g_test_header, .iov_len = 16},
    .value  = {.iov_base = g_test_header, .iov_len = 4096},
    .flags  = 1,
};

xqc_http_header_t g_static_header = {
    .name   = {.iov_base = ":method", .iov_len = sizeof(":method") - 1},
    .value  = {.iov_base = "GET", .iov_len = sizeof("GET") - 1},
    .flags  = 0,
};

xqc_http_header_t g_static_name_idx_header = {
    .name   = {.iov_base = ":method", .iov_len = sizeof(":method") - 1},
    .value  = {.iov_base = "literial_post", .iov_len = sizeof("literial_post") - 1},
    .flags  = 0,
};


xqc_http_header_t g_literial_header = {
    .name   = {.iov_base = "literial_method_test_insert", .iov_len = sizeof("literial_method_test_insert") - 1},
    .value  = {.iov_base = "literial_post_test_insert", .iov_len = sizeof("literial_post_test_insert") - 1},
    .flags  = 0,
};

xqc_http_header_t g_literial_header_with_flag = {
    .name   = {.iov_base = "literial_content-type_test_never_flag", .iov_len = sizeof("literial_content-type_test_never_flag") - 1},
    .value  = {.iov_base = "literial_text/plain_test_never_flag", .iov_len = sizeof("literial_text/plain_test_never_flag") - 1},
    .flags  = 1,

};

xqc_http_header_t g_test_name_idx_header = {
    .name   = {.iov_base = "literial_method_test_insert", .iov_len = sizeof("literial_method_test_insert") - 1},
    .value  = {.iov_base = "test_name_idx_post_test_insert", .iov_len = sizeof("test_name_idx_post_test_insert") - 1},
    .flags  = 0,
};

user_stream_t * g_user_stream = NULL;
user_stream_t * g_drain_user_stream = NULL;
user_stream_t * g_drain_user_stream1 = NULL;
user_stream_t * g_test_idx_user_stream = NULL;
user_stream_t * g_test_array_user_stream = NULL;
user_stream_t * g_test_name_idx_user_stream = NULL;

int xqc_decoder_check_insert_result(xqc_http3_qpack_decoder * decoder, xqc_http_header_t * header){
    size_t name_len = header->name.iov_len;
    char * value = header->value.iov_base;
    size_t value_len = header->value.iov_len;
    uint8_t flags = header->flags;


    return 0;

}


int xqc_encoder_check_header_can_be_ref(xqc_h3_conn_t * h3_conn, xqc_http_header_t * header){
    xqc_http3_qpack_encoder * encoder = xqc_get_http3_qpack_encoder(h3_conn);

    char * name = header->name.iov_base;

    size_t name_len = header->name.iov_len;
    char * value = header->value.iov_base;
    size_t value_len = header->value.iov_len;
    uint8_t flags = header->flags;
    xqc_qpack_find_result d_result;


    xqc_http3_qpack_hash_find(&(encoder->dtable_hash), &(encoder->ctx.dtable_data), name, name_len, value, value_len, &d_result);

    if(d_result.entry){
        if(d_result.entry->absidx < encoder->krcnt){
            return 2;
        }else{
            return 1;
        }
    }else{
        return 0;
    }


    return -1;
}

int xqc_encoder_check_insert_result(xqc_h3_conn_t * h3_conn, xqc_http_header_t * header){

    xqc_http3_qpack_encoder * encoder = xqc_get_http3_qpack_encoder(h3_conn);

    char * name = header->name.iov_base;

    size_t name_len = header->name.iov_len;
    char * value = header->value.iov_base;
    size_t value_len = header->value.iov_len;
    uint8_t flags = header->flags;
    xqc_qpack_find_result d_result;


    xqc_http3_qpack_hash_find(&(encoder->dtable_hash), &(encoder->ctx.dtable_data), name, name_len, value, value_len, &d_result);


    if(header->flags == 0){
        if(d_result.entry){
            printf("***** qpack test insert literial [1] pass\n\n");
        }else{
            printf("----- qpack test insert literial [1] failed\n\n");
        }
    }else{
        if(d_result.entry == NULL){
            printf("***** qpack test never flag [2] pass\n\n");
        }else{
            printf("----- qpack test never flag [2] failed\n\n");
        }
    }

    return 0;
}



int xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream, xqc_http_header_t * header, int count)
{
    ssize_t ret = 0;
    xqc_http_headers_t headers = {
            .headers = header,
            .count  = count,
    };

    int header_only = 0;
    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

    }

    if (header_only) {
        return 0;
    }

    return 0;
}

int xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
//xqc_h3_request_close(h3_request);
    //xqc_client_request_send(h3_request, user_stream, &g_literial_header);


    return ret;
}

int xqc_client_request_read_notify(xqc_h3_request_t *h3_request, void *user_data, xqc_request_notify_flag_t flag)
{
    DEBUG;
    int ret;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    int success_flag = 0;
    int draining_flag = 0;
    static int test_name_value_result = 0;
    static int test_name_idx_result = 0;
    static int test_static_result = 0;
    static int test_static_name_idx_result = 0;
    static int test_draining_result = 0;
    //if (user_stream->header_recvd == 0) {
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        if(headers->count != sizeof(g_array_literial_header) / sizeof(g_array_literial_header[0])){
            //printf("qpack test literial failed");
            success_flag++;
        }
        int i = 0;
        for (i = 0; i < headers->count; i++) {
            printf("header name:%s value:%s\n",(char *)(headers->headers[i].name.iov_base), (char *)(headers->headers[i].value.iov_base));
            if((headers-> headers[i].name.iov_len != g_array_literial_header[i].name.iov_len) ||
                    (0 != memcmp(headers->headers[i].name.iov_base, g_array_literial_header[i].name.iov_base, headers->headers[i].name.iov_len) )){
                success_flag++;
            }


            if((headers->headers[i].name.iov_len == g_literial_header.name.iov_len)
                    && (0 == memcmp(headers->headers[i].name.iov_base, g_literial_header.name.iov_base, headers->headers[i].name.iov_len))
                    && (headers->headers[i].value.iov_len == g_literial_header.value.iov_len)
                    && (0 == memcmp(headers->headers[i].value.iov_base, g_literial_header.value.iov_base, headers->headers[i].value.iov_len))
              ){
                    test_name_value_result++;
            }

             if((headers->headers[i].name.iov_len == g_test_name_idx_header.name.iov_len)
                    && (0 == memcmp(headers->headers[i].name.iov_base, g_test_name_idx_header.name.iov_base, headers->headers[i].name.iov_len))
                    && (headers->headers[i].value.iov_len == g_test_name_idx_header.value.iov_len)
                    && (0 == memcmp(headers->headers[i].value.iov_base, g_test_name_idx_header.value.iov_base, headers->headers[i].value.iov_len))
              ){
                    test_name_idx_result++;
            }


             if((headers->headers[i].name.iov_len == g_static_header.name.iov_len)
                    && (0 == memcmp(headers->headers[i].name.iov_base, g_static_header.name.iov_base, headers->headers[i].name.iov_len))
                    && (headers->headers[i].value.iov_len == g_static_header.value.iov_len)
                    && (0 == memcmp(headers->headers[i].value.iov_base, g_static_header.value.iov_base, headers->headers[i].value.iov_len))
              ){
                    test_static_result++;
            }

             if((headers->headers[i].name.iov_len == g_static_name_idx_header.name.iov_len)
                    && (0 == memcmp(headers->headers[i].name.iov_base, g_static_name_idx_header.name.iov_base, headers->headers[i].name.iov_len))
                    && (headers->headers[i].value.iov_len == g_static_name_idx_header.value.iov_len)
                    && (0 == memcmp(headers->headers[i].value.iov_base, g_static_name_idx_header.value.iov_base, headers->headers[i].value.iov_len))
              ){
                    test_static_name_idx_result++;
            }

             if((headers->headers[i].name.iov_len == g_array_draining_header[i].name.iov_len)
                    && (0 == memcmp(headers->headers[i].name.iov_base, g_array_draining_header[i].name.iov_base, headers->headers[i].name.iov_len))
                    && (headers->headers[i].value.iov_len == g_array_draining_header[i].value.iov_len)
                    && (0 == memcmp(headers->headers[i].value.iov_base, g_array_draining_header[i].value.iov_base, headers->headers[i].value.iov_len))
              ){
                    draining_flag++;
            }



        }


        if(draining_flag == 4){

            xqc_client_request_send(g_drain_user_stream1->h3_request, g_drain_user_stream1, g_array_draining_header, 1);
        }

        if(draining_flag == 1){
            printf("***** qpack test draining [8] pass\n\n");
        }

        xqc_h3_conn_t * h3_conn = h3_request->h3_stream->h3_conn;
        if(xqc_encoder_check_header_can_be_ref(h3_conn, &g_literial_header) == 2){
            //printf("qpack test *******************************\n");
            if(g_test_idx_user_stream){

                xqc_client_request_send(g_test_idx_user_stream->h3_request, g_test_idx_user_stream, &g_literial_header, 1);
            }

            if(g_test_name_idx_user_stream){

                xqc_client_request_send(g_test_name_idx_user_stream->h3_request, g_test_name_idx_user_stream, &g_test_name_idx_header, 1);
                //xqc_client_request_send(g_test_name_idx_user_stream->h3_request, g_test_name_idx_user_stream, &g_literial_header, 1);
            }

            if(g_drain_user_stream){

                xqc_client_request_send(g_drain_user_stream->h3_request, g_drain_user_stream, g_array_draining_header, 4);

            }
        }else{

            if (user_stream->send_body == NULL) {
                user_stream->send_body_max = 1024;
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, "client_send_body");
                if (ret < 0) {
                    printf("read body error\n");
                    /*文件不存在则发内存数据*/
                    user_stream->send_body_len = 1024;
                } else {
                    user_stream->send_body_len = ret;
                }
            }

            if (user_stream->send_offset < user_stream->send_body_len) {
                ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
                if (ret < 0) {
                    printf("xqc_h3_request_send_body error %d\n", ret);
                    return ret;
                } else {
                    user_stream->send_offset += ret;
                    //printf("xqc_h3_request_send_body offset=%llu\n", user_stream->send_offset);
                }
            }

            if(g_user_stream){
                //printf("qpack test ---------------------------------\n");
                //xqc_client_request_send(g_user_stream->h3_request, g_user_stream, &g_header, 1);
            }
        }


        if(success_flag == 0){
            printf("***** qpack test literial [3] pass\n\n");

            if(g_test_name_idx_user_stream){

                //xqc_client_request_send(g_test_name_idx_user_stream->h3_request, g_test_name_idx_user_stream, &g_test_name_idx_header, 1);
            }



        }

        if(test_name_value_result < 0){

            printf("test_name_value_result value:%d\n", test_name_value_result);
        }


        if(test_name_value_result == 2){
            test_name_value_result = -100;
            printf("***** qpack test name value index [6] pass\n\n");
        }

        if(test_name_idx_result == 1){
            test_name_idx_result = 0;
            printf("***** qpack test name index [7] pass\n\n");
        }

        if(test_static_result == 1){
            test_static_result = 0;
            printf("***** qpack test static name value index [4] pass\n\n");
        }

        if(test_static_name_idx_result == 1){
            test_static_name_idx_result = 0;
            printf("***** qpack test static name index [5] pass\n\n");
        }



        user_stream->header_recvd = 1;

        if (fin) {
            /* 只有header，请求接收完成，处理业务逻辑 */
            return 0;
        }
        //继续收body
    }

#if 0
    char buff[4096] = {0};
    size_t buff_size = 4096;

    int save = 1;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen("client_recv_body", "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    ssize_t read;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        printf("xqc_h3_request_recv_body %lld, fin:%d\n", read, fin);
        if(save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if(save) fflush(user_stream->recv_body_fp);
    } while (read > 0 && !fin);
#endif
    return 0;
}

int xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu\n", stats.send_body_size, stats.recv_body_size);

    free(user_stream);
    return 0;
}

void
xqc_client_write_handler(user_conn_t *user_conn)
{
    DEBUG
    xqc_conn_continue_send(ctx.engine, &user_conn->cid);
}


void
xqc_client_read_handler(user_conn_t *user_conn)
{
    DEBUG

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
        //printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n", recv_size, recv_time);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

        if (xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&user_conn->local_addr), user_conn->local_addrlen,
                                      (struct sockaddr *) (&user_conn->peer_addr), user_conn->peer_addrlen,
                                      (xqc_msec_t) recv_time, user_conn) != 0) {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);
    xqc_engine_main_logic(ctx.engine);
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
    //printf("xqc_client_timer_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    //printf("xqc_client_timeout_callback now %llu\n", now());
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
    return user_stream;

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

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   0,
            //.cong_ctrl_callback = xqc_reno_cb,
            .cong_ctrl_callback = xqc_cubic_cb,
            //.cong_ctrl_callback = xqc_bbr_cb,
    };

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, &ctx);

    user_conn_t *user_conn;
    user_conn = calloc(1, sizeof(user_conn_t));

    //是否使用http3
    user_conn->h3 = 1;
    //user_conn->h3 = 0;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* 设置连接超时 */
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    user_conn->fd = xqc_client_create_socket(user_conn, server_addr, server_port);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, xqc_client_event_callback, user_conn);
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

    if (session_len < 0 || tp_len < 0) {
        printf("sessoin data read error");
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

    //xqc_set_save_session_cb(ctx.engine, cid, (xqc_save_session_cb_t)save_session_cb, cid);
    //xqc_set_save_tp_cb(ctx.engine, cid, (xqc_save_tp_cb_t) save_tp_cb, cid);

    user_stream_t *user_stream = create_user_stream(ctx.engine, user_conn, cid) ;
    user_stream_t *user_stream1 = create_user_stream(ctx.engine, user_conn, cid) ;
    user_stream_t *user_stream2 = create_user_stream(ctx.engine, user_conn, cid) ;
    user_stream_t *user_stream3 = create_user_stream(ctx.engine, user_conn, cid) ;
    user_stream_t *user_stream4 = create_user_stream(ctx.engine, user_conn, cid) ;
    user_stream_t *user_stream5 = create_user_stream(ctx.engine, user_conn, cid);
    user_stream_t *user_stream6 = create_user_stream(ctx.engine, user_conn, cid);
    user_stream_t *user_stream7 = create_user_stream(ctx.engine, user_conn, cid);
    user_stream_t *user_stream8 = create_user_stream(ctx.engine, user_conn, cid);
    user_stream_t *user_stream9 = create_user_stream(ctx.engine, user_conn, cid);
    user_stream_t *user_stream10 = create_user_stream(ctx.engine, user_conn, cid);



    g_test_array_user_stream = user_stream2;
    g_test_idx_user_stream = user_stream3;
    g_test_name_idx_user_stream = user_stream4;
    g_user_stream = user_stream5;
    g_drain_user_stream = user_stream9;
    g_drain_user_stream1 = user_stream10;
    if (user_conn->h3) {
        //xqc_client_request_send(user_stream8->h3_request, user_stream8, g_array_refresh_header, 3);

        //xqc_client_request_send(user_stream8->h3_request, user_stream8, g_array_refresh_header, 3);
        xqc_client_request_send(user_stream->h3_request, user_stream, &g_literial_header, 1);
        xqc_h3_stream_t * h3_stream = user_stream->h3_request->h3_stream;
        xqc_h3_conn_t * h3_conn = h3_stream->h3_conn;
        xqc_encoder_check_insert_result(h3_conn, &g_literial_header);

        xqc_client_request_send(user_stream1->h3_request, user_stream1, &g_literial_header_with_flag, 1);
        xqc_encoder_check_insert_result(h3_conn, &g_literial_header_with_flag);

        xqc_client_request_send(user_stream2->h3_request, user_stream2, g_array_literial_header, 3);

        xqc_client_request_send(user_stream6->h3_request, user_stream6, &g_static_header, 1);
        xqc_client_request_send(user_stream7->h3_request, user_stream7, &g_static_name_idx_header, 1);


    } else {
        xqc_client_stream_send(user_stream->stream, user_stream);
    }

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
