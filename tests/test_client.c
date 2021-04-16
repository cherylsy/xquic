#define _GNU_SOURCE
#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

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

#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_SHORT_HEADER_PACKET_B "\x80\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define MAX_HEADER 100

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
    xqc_msec_t          first_frame_time; //首帧下载时间
    xqc_msec_t          last_read_time;
    int                 abnormal_count;
} user_stream_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    int                 h3;
} user_conn_t;

#define XQC_DEMO_INTERFACE_MAX_LEN 64
#define XQC_DEMO_MAX_PATH_COUNT    8

typedef struct xqc_user_path_s {
    int                 path_fd;
    uint64_t            path_id;
    
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;
    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;

    struct event       *ev_socket;
} xqc_user_path_t;


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
uint64_t g_last_sock_op_time;
//currently, the maximum used test case id is 19
//please keep this comment updated if you are adding more test cases. :-D
int g_test_case;
int g_ipv6;
int g_no_crypt;
int g_conn_timeout = 3;
char g_write_file[64];
char g_read_file[64];
char g_host[64] = "test.xquic.com";
char g_url_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[2048];
char g_headers[MAX_HEADER][256];
int g_header_cnt = 0;
int g_ping_id = 1;
int g_enable_multipath = 0;
char g_multi_interface[XQC_DEMO_MAX_PATH_COUNT][64];
xqc_user_path_t g_client_path[XQC_DEMO_MAX_PATH_COUNT];
int g_multi_interface_cnt = 0;


static uint64_t last_recv_ts = 0;

static void xqc_client_socket_event_callback(int fd, short what, void *arg);
static void xqc_client_timeout_callback(int fd, short what, void *arg);


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

void save_session_cb( char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void save_tp_cb(char * data, size_t data_len, void * user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void xqc_client_save_token(void *user_data, const unsigned char *token, unsigned token_len)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    if (g_test_case == 16) { /* test application delay */
        usleep(300*1000);
    }
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
ssize_t 
xqc_client_write_socket(void *user, 
    unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;
    //printf("xqc_client_write_socket size=%zd, now=%llu, send_total=%d\n",size, now(), ++g_send_total);
    do {
        errno = 0;
        //res = write(fd, buf, size);
        if (TEST_DROP) return size;
        if (g_test_case == 5/*socket写失败*/) {g_test_case = -1; errno = EAGAIN; return XQC_SOCKET_EAGAIN;}

        // client Initial dcid corruption ...
        if (g_test_case == 22) {
            /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
            g_test_case = -1;
            buf[6] = ~buf[6];
            printf("test case 22, corrupt byte[6]\n");
        }

        // client Initial scid corruption ...
        if (g_test_case == 23) {
            /* bytes [15, 22] is the SCID of xquic's Initial packet */
            g_test_case = -1;
            buf[15] = ~buf[15];
            printf("test case 23, corrupt byte[15]\n");
        }

        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        //printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
        g_last_sock_op_time = now();
    } while ((res < 0) && (errno == EINTR));
    /*socklen_t tmp = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&user_conn->local_addr, &tmp);*/


    return res;
}


ssize_t 
xqc_client_write_mmsg(void *user, struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen)
{
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = &msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        errno = 0;
        if (TEST_DROP) return vlen;
        if (g_test_case == 5/*socket写失败*/) {g_test_case = -1; errno = EAGAIN; return XQC_SOCKET_EAGAIN;}
        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}


static int 
xqc_client_create_socket(int type, 
    const struct sockaddr *saddr, socklen_t saddr_len)
{
    int fd = -1;

    /* create fd & set socket option */
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

    g_last_sock_op_time = now();

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }
#endif

    return fd;

  err:
    close(fd);
    return -1;
}


void 
xqc_convert_addr_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len)
{
    if (type == AF_INET6) {
        *saddr = calloc(1, sizeof(struct sockaddr_in6));
        memset(*saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)(*saddr);
        inet_pton(type, addr_text, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in6);
    } else {
        *saddr = calloc(1, sizeof(struct sockaddr_in));
        memset(*saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
        inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in);
    }
}

void
xqc_client_init_addr(user_conn_t *user_conn,
    const char *server_addr, int server_port)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_convert_addr_text_to_sockaddr(ip_type, 
                                      server_addr, server_port,
                                      &user_conn->peer_addr, 
                                      &user_conn->peer_addrlen);

    if (ip_type == AF_INET6) {
        user_conn->local_addr = calloc(1, sizeof(struct sockaddr_in6));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in6));
        user_conn->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        user_conn->local_addr = calloc(1, sizeof(struct sockaddr_in));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in));
        user_conn->local_addrlen = sizeof(struct sockaddr_in);
    }
}



static int
xqc_client_bind_to_interface(int fd, 
    const char *interface_name)
{
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, strlen(interface_name));

    printf("bind to nic: %s\n", interface_name);

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
        printf("bind to nic error: %d, try use sudo\n", errno);
        return XQC_ERROR;
    }

    return XQC_OK;
}


static int
xqc_client_create_path_socket(xqc_user_path_t *path,
    char *path_interface)
{
    path->path_fd = xqc_client_create_socket((g_ipv6 ? AF_INET6 : AF_INET), 
                                             path->peer_addr, path->peer_addrlen);
    if (path->path_fd < 0) {
        printf("|xqc_client_create_path_socket error|");
        return XQC_ERROR;
    }

    if (path_interface != NULL
        && xqc_client_bind_to_interface(path->path_fd, path_interface) < 0) 
    {
        printf("|xqc_client_bind_to_interface error|");
        return XQC_ERROR;
    }

    return XQC_OK;
}


static int
xqc_client_create_path(xqc_user_path_t *path, 
    char *path_interface, user_conn_t *user_conn)
{
    path->peer_addr = calloc(1, user_conn->peer_addrlen);
    memcpy(path->peer_addr, user_conn->peer_addr, user_conn->peer_addrlen);
    path->peer_addrlen = user_conn->peer_addrlen;
    
    if (xqc_client_create_path_socket(path, path_interface) < 0) {
        printf("xqc_client_create_path_socket error\n");
        return XQC_ERROR;
    }
    
    path->ev_socket = event_new(eb, path->path_fd, 
                EV_READ | EV_PERSIST, xqc_client_socket_event_callback, user_conn);
    event_add(path->ev_socket, NULL);

    return XQC_OK;
}


user_conn_t * 
xqc_client_user_conn_create(const char *server_addr, int server_port,
    int transport)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));

    /* 是否使用http3 */
    user_conn->h3 = transport ? 0 : 1;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* 设置连接超时 */
    struct timeval tv;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);
                                      
    user_conn->fd = xqc_client_create_socket(ip_type, 
                                             user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return NULL;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, 
                                     xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return user_conn;
}


int xqc_client_conn_create_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    printf("xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int xqc_client_conn_close_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    event_base_loopbreak(eb);
    return 0;
}

void xqc_client_conn_ping_acked_notify(xqc_connection_t *conn, xqc_cid_t *cid, void *user_data, void *ping_user_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("ping_id:%d\n", *(int *) ping_user_data);
    }
    return;
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
    if (g_test_case == 18) { /* test h3 settings */
        xqc_h3_conn_settings_t settings = {
                .max_field_section_size = 256,
                .qpack_max_table_capacity = 4096,
                .qpack_blocked_streams = 32,
        };
        xqc_h3_conn_set_settings(conn, settings);
    }

    if (g_test_case == 19) { /* test header size constraints */
        xqc_h3_conn_settings_t settings = {
                .max_field_section_size = 100,
        };
        xqc_h3_conn_set_settings(conn, settings);
    }

    printf("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn errno:%d\n", xqc_h3_conn_get_errno(conn));

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    event_base_loopbreak(eb);
    return 0;
}

void xqc_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);

    if (g_test_case == 25) {
        printf("transport_parameter:enable_multipath=%d\n", stats.enable_multipath);
    }
}

void xqc_client_h3_conn_ping_acked_notify(xqc_h3_conn_t *conn, xqc_cid_t *cid, void *user_data, void *ping_user_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("ping_id:%d\n", *(int *) ping_user_data);
    }
}

int xqc_client_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->start_time == 0) {
        user_stream->start_time = now();
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
        ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
        }
    }
    if (g_test_case == 4) { //test fin_only
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_stream_send sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }

    return 0;
}

int xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_client_stream_send(stream, user_stream);
    return ret;
}

int xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
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
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;
        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
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

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    if (g_test_case == 14/*测试秒开率*/ && user_stream->first_frame_time == 0 && user_stream->recv_body_len >= 98*1024) {
        user_stream->first_frame_time = now();
    }

    if (g_test_case == 14/*测试卡顿率*/) {
        xqc_msec_t tmp = now();
        if (tmp - user_stream->last_read_time > 150*1000 && user_stream->last_read_time != 0 ) {
            user_stream->abnormal_count++;
            printf("\033[33m!!!!!!!!!!!!!!!!!!!!abnormal!!!!!!!!!!!!!!!!!!!!!!!!\033[0m\n");
        }
        user_stream->last_read_time = tmp;
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_msec_t now_us = now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (user_stream->send_body_len + user_stream->recv_body_len)*1000/(now_us - user_stream->start_time),
               user_stream->send_body_len, user_stream->recv_body_len);

        // write to eval file
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL){
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

    }
    return 0;
}

int xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    if (g_echo_check) {
        int pass = 0;
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
            pass = 1;
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }
    if (g_test_case == 14/*测试秒开率*/ ) {
        printf("first_frame_time: %"PRIu64", start_time: %"PRIu64"\n", user_stream->first_frame_time, user_stream->start_time);
        xqc_msec_t t = user_stream->first_frame_time - user_stream->start_time + 200000/*服务端处理耗时*/;
        printf("\033[33m>>>>>>>> first_frame pass:%d time:%"PRIu64"\033[0m\n", t <= 1000000 ? 1 : 0, t);
    }

    if (g_test_case == 14/*测试卡顿率*/ ) {
        printf("\033[33m>>>>>>>> abnormal pass:%d count:%d\033[0m\n", user_stream->abnormal_count == 0 ? 1 : 0, user_stream->abnormal_count);
    }
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);
    return 0;
}

int xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    if (user_stream->start_time == 0) {
        user_stream->start_time = now();
    }
    ssize_t ret = 0;
    char content_len[10];
    if (g_is_get) {
        snprintf(content_len, sizeof(content_len), "%d", 0);

    } else {
        snprintf(content_len, sizeof(content_len), "%d", g_send_body_size);
    }
    int header_size = 6;
    xqc_http_header_t header[MAX_HEADER] = {
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
                    .value  = {.iov_base = g_url_path, .iov_len = strlen(g_url_path)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = "content-type", .iov_len = 12},
                    .value  = {.iov_base = "text/plain", .iov_len = 10},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = "content-length", .iov_len = 14},
                    .value  = {.iov_base = content_len, .iov_len = strlen(content_len)},
                    .flags  = 0,
            },
    };

    if (g_header_cnt > 0) {
        for (int i = 0; i < g_header_cnt; i++) {
            char *pos = strchr(g_headers[i], ':');
            if (pos == NULL) {
                continue;
            }
            header[header_size].name.iov_base = g_headers[i];
            header[header_size].name.iov_len = pos - g_headers[i];
            header[header_size].value.iov_base = pos + 1;
            header[header_size].value.iov_len = strlen(pos+1);
            header[header_size].flags = 0;
            header_size++;
        }
    }

    xqc_http_headers_t headers = {
            .headers = header,
            .count  = header_size,
    };

    int header_only = g_is_get;
    if (g_is_get) {
         header[0].value.iov_base = "GET";
         header[0].value.iov_len = sizeof("GET") - 1;
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
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;
        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }
    if (g_test_case == 4) { //test fin_only
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }
    return 0;
}

int xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    if (g_test_case == 1/*Reset stream*/) {
        xqc_h3_request_close(h3_request);
        return 0;
    }
    if (g_test_case == 2/*主动关闭连接*/) {
        xqc_h3_conn_close(ctx.engine, &user_stream->user_conn->cid);
        return 0;
    }
    if (g_test_case == 3/*流可写通知失败；出错关闭连接*/) {
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

    if (g_test_case == 21/*Reset stream*/) {
        xqc_h3_request_close(h3_request);
        return 0;
    }
    if (g_test_case == 12/*流读通知失败*/) { return -1;}
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
        if (read == -XQC_EAGAIN) {
            break;
        } else if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return 0;
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
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size)*1000/(now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size);

        // write to eval file
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL){
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

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
    printf("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, recv_fin:%d, err:%d\n",
           stats.send_body_size, stats.recv_body_size,
           stats.send_header_size, stats.recv_header_size,
           user_stream->recv_fin, stats.stream_err);

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
        if (user_stream->h3_request == NULL) {
            printf("xqc_h3_request_create error\n");
            return 0;
        }
        xqc_client_request_send(user_stream->h3_request, user_stream);
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

#ifdef __linux__
    int batch = 0;
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
                msgs[i].msg_hdr.msg_namelen = user_conn->peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(user_conn->fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(ctx.engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              user_conn->local_addr, user_conn->local_addrlen,
                                              user_conn->peer_addr, user_conn->peer_addrlen,
                                              (xqc_msec_t) recv_time, user_conn) != 0) 
                {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;


    if (g_test_case == 24) {
        exit(0);
    }

    do {
        recv_size = recvfrom(user_conn->fd, 
                             packet_buf, sizeof(packet_buf), 0, 
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(errno));
            break;
        }

        /* if recv_size is 0, break while loop, */
        if (recv_size == 0) {
            break;
        }

        recv_sum += recv_size;
        rcv_sum += recv_size;

        if (user_conn->local_addrlen == 0) {
            socklen_t tmp = sizeof(struct sockaddr_in6);
            getsockname(user_conn->fd, (struct sockaddr *) &user_conn->local_addr, &tmp);
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = now();
        g_last_sock_op_time = recv_time;

        //printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n", recv_size, recv_time);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(user_conn->peer_addr.sin_addr), ntohs(user_conn->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(user_conn->local_addr.sin_addr), ntohs(user_conn->local_addr.sin_port));*/

        if (TEST_DROP) continue;
        if (g_test_case == 6/*socket读失败*/) {g_test_case = -1; break;}
        if (g_test_case == 8/*接收到不存在连接的包*/) {g_test_case = -1; recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1; memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_A, recv_size);}
        static char copy[XQC_PACKET_TMP_BUF_LEN];
        if (g_test_case == 9/*接收到重复的包*/) {memcpy(copy, packet_buf, recv_size); again:;}
        if (g_test_case == 10/*不合法的packet*/) {g_test_case = -1; recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_B)-1; memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_B, recv_size);}
        if (xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                      user_conn->local_addr, user_conn->local_addrlen,
                                      user_conn->peer_addr, user_conn->peer_addrlen,
                                      (xqc_msec_t) recv_time, user_conn) != 0) {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }
        if (g_test_case == 9/*接收到重复的包*/) {g_test_case = -1; memcpy(packet_buf, copy, recv_size); goto again;}
    } while (recv_size > 0);

    if ((now() - last_recv_ts) > 200000) {
        printf("recving rate: %.3lf Kbps\n", (rcv_sum - last_rcv_sum) * 8.0 * 1000 / (now() - last_recv_ts));
        last_recv_ts = now();
        last_rcv_sum = rcv_sum;
    }

finish_recv:
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
    printf("timer wakeup now:%"PRIu64"\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timeout_callback now %"PRIu64"\n", now());
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    static int restart_after_a_while = 1;

    // write to eval file
    /*{
        FILE* fp = NULL;
        fp = fopen("eval_result.txt", "a+");
        if (fp == NULL){
            exit(1);
        }

        fprintf(fp, "recv_size: %u; cost_time: %u\n", 11, 60 * 1000);
        fclose(fp);

    }*/
    //Test case 15: testing restart from idle
    if (restart_after_a_while && g_test_case == 15) {
        restart_after_a_while--;
        //we don't care the memory leak caused by user_stream. It's just for one-shot testing. :D
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        memset(user_stream, 0, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        printf("gtest 15: restart from idle!\n");
        user_stream->stream = xqc_stream_create(ctx.engine, &(user_conn->cid), user_stream);
        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            goto conn_close;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        printf("scheduled a new stream request\n");
        return;
    }

    if (now() - g_last_sock_op_time < (uint64_t)g_conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

conn_close:
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
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/clog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
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
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+\n"
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
"   -H    Header. eg. key:value\n"
"   -h    Host & sni. eg. test.xquic.com\n"
"   -G    GET on. Default is POST\n"
"   -x    Test case ID\n"
"   -N    No encryption\n"
"   -6    IPv6\n"
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
    g_ipv6 = 0;
    g_no_crypt = 0;

    char server_addr[64] = TEST_SERVER_ADDR;
    int server_port = TEST_SERVER_PORT;
    int req_paral = 1;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    int transport = 0;
    int use_1rtt = 0;

    int ch = 0;
    while((ch = getopt(argc, argv, "a:p:P:n:c:Ct:T1s:w:r:l:Ed:u:H:h:Gx:6NMi:")) != -1){
        switch(ch)
        {
            case 'a':
                printf("option addr :%s\n", optarg);
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
            case 'c': //拥塞算法 r:reno b:bbr c:cubic B:bbr2
                c_cong_ctl = optarg[0];
                if (strncmp("bbr2", optarg, 4) == 0)
                    c_cong_ctl = 'B';
                if (strncmp("bbr2+", optarg, 5) == 0
                    || strncmp("bbr+", optarg, 4) == 0)
                    c_cong_plus = 1;
                printf("option cong_ctl : %c: %s: plus? %d\n", c_cong_ctl, optarg, c_cong_plus);
                break;
            case 'C': //pacing on
                printf("option pacing :%s\n", "on");
                pacing_on = 1;
                break;
            case 't': //n秒后关闭连接
                printf("option g_conn_timeout :%s\n", optarg);
                g_conn_timeout = atoi(optarg);
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
                sscanf(g_url,"%[^://]://%[^/]%s", g_scheme, g_host, g_url_path);
                break;
            case 'H': //请求header
                printf("option header :%s\n", optarg);
                snprintf(g_headers[g_header_cnt], sizeof(g_headers[g_header_cnt]), optarg);
                g_header_cnt++;
                break;
            case 'h': /* host & sni */
                printf("option host & sni :%s\n", optarg);
                snprintf(g_host, sizeof(g_host), optarg);
                break;
            case 'G': //Get请求
                printf("option get :%s\n", "on");
                g_is_get = 1;
                break;
            case 'x': //test case id
                printf("option test case id: %s\n", optarg);
                g_test_case = atoi(optarg);
                break;
            case '6': //IPv6
                printf("option IPv6 :%s\n", "on");
                g_ipv6 = 1;
                break;
            case 'N':
                printf("option No crypt: %s\n", "yes");
                g_no_crypt = 1;
                break;
            case 'M':
                printf("option enable multi-path: %s\n", "yes");
                g_enable_multipath = 1;
                break;
            case 'i':
                printf("option multi-path: %s\n", optarg);
                ++g_multi_interface_cnt;
                memset(g_multi_interface[g_multi_interface_cnt], 0, XQC_DEMO_INTERFACE_MAX_LEN);
                snprintf(g_multi_interface[g_multi_interface_cnt], 
                         XQC_DEMO_INTERFACE_MAX_LEN, optarg);
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
                    .conn_ping_acked = xqc_client_conn_ping_acked_notify,
            },
            .h3_conn_callbacks = {
                    .h3_conn_create_notify = xqc_client_h3_conn_create_notify, /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
                    .h3_conn_close_notify = xqc_client_h3_conn_close_notify, /* 连接关闭时回调,用户可以回收资源 */
                    .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished, /* 握手完成时回调 */
                    .h3_conn_ping_acked = xqc_client_h3_conn_ping_acked_notify,
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
                    .log_level = c_log_level == 'e' ? XQC_LOG_ERROR : (c_log_level == 'i' ? XQC_LOG_INFO : c_log_level == 'w'? XQC_LOG_STATS: XQC_LOG_DEBUG),
                    //.log_level = XQC_LOG_INFO,
                    .xqc_open_log_file = xqc_client_open_log_file,
                    .xqc_close_log_file = xqc_client_close_log_file,
                    .xqc_write_log_file = xqc_client_write_log_file,
            },
            .save_session_cb = save_session_cb,
            .save_tp_cb = save_tp_cb,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus)
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
#endif
    }
#ifndef XQC_DISABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
        cong_flags = XQC_BBR2_FLAG_NONE;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
    else if (c_cong_ctl == 'C') {
        cong_ctrl = xqc_cubic_kernel_cb;
    } else {
        printf("unknown cong_ctrl, option is b, r, c, B, bbr+, bbr2+\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   pacing_on,
            .ping_on    =   0,
            .cong_ctrl_callback = cong_ctrl,
            .cc_params  =   {.customize_on = 1, .init_cwnd = 32, .cc_optimization_flags = cong_flags},
            //.so_sndbuf  =   1024*1024,
            .proto_version = XQC_IDRAFT_VER_29,
            .spurious_loss_detect_on = 0,
    };

    /* check initial version */
    if (g_test_case == 17) {
        conn_settings.proto_version = XQC_IDRAFT_INIT_VER;
    }
    if (g_test_case == 20) { /* test sendmmsg */
        printf("test sendmmsg!\n");
        callback.write_mmsg = xqc_client_write_mmsg;
    }
    if (g_test_case == 24) {
        conn_settings.idle_time_out = 10000;
    }

    /* enable_multipath */
    if (g_test_case == 25) {
        conn_settings.enable_multipath = 1;
    }

    /* test spurious loss detect */
    if (g_test_case == 26) {
        conn_settings.spurious_loss_detect_on = 1;
    }

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    if (g_test_case == 13) {//test different cid_len
        xqc_config_t config;
        config.cid_len = XQC_MAX_CID_LEN;
        xqc_set_engine_config(&config, XQC_ENGINE_CLIENT);
    }

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, &ctx);
    if (ctx.engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    user_conn_t *user_conn = xqc_client_user_conn_create(server_addr, server_port, transport);
    if (user_conn == NULL) {
        printf("xqc_client_user_conn_create error\n");
        return -1;
    }

    if (g_enable_multipath) {

        for (int i = 1; i <= g_multi_interface_cnt; ++i) {
            if (xqc_client_create_path(&g_client_path[i], g_multi_interface[i], user_conn) != XQC_OK) {
                printf("xqc_client_create_path %d error\n", i);
                return 0;
            }
        }
    }

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
        if (g_test_case == 7/*创建连接失败*/) {user_conn->token_len = -1;}
        cid = xqc_h3_connect(ctx.engine, user_conn, conn_settings, user_conn->token, user_conn->token_len, g_host, g_no_crypt,
                          &conn_ssl_config, user_conn->peer_addr, user_conn->peer_addrlen);
    } else {
        cid = xqc_connect(ctx.engine, user_conn, conn_settings, user_conn->token, user_conn->token_len, "127.0.0.1", g_no_crypt,
                          &conn_ssl_config, user_conn->peer_addr, user_conn->peer_addrlen);
    }
    if (cid == NULL) {
        printf("xqc_connect error\n");
        xqc_engine_destroy(ctx.engine);
        return 0;
    }
    /* cid要copy到自己的内存空间，防止内部cid被释放导致crash */
    memcpy(&user_conn->cid, cid, sizeof(*cid));
    //xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);
    for (int i = 0; i < req_paral; i++) {
        g_req_cnt++;
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        if (user_conn->h3) {
            if (g_test_case == 11/*创建流失败*/) {xqc_cid_t tmp; xqc_h3_request_create(ctx.engine, &tmp, user_stream); continue;}
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
    last_recv_ts = now();
    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
