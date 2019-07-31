#include <stdio.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include "../congestion_control/xqc_new_reno.h"
#include "../congestion_control/xqc_cubic.h"
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <transport/xqc_stream.h>
#include "../include/xquic_typedef.h"
#include "../transport/crypto/xqc_tls_header.h"
#include "transport/xqc_conn.h"


#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);


#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500


typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;

    xqc_stream_t       *stream;
    unsigned char      *token;
    unsigned            token_len;
} user_conn_t;

typedef struct client_ctx_s {
    xqc_engine_t  *engine;
    user_conn_t   *my_conn;
    struct event  *ev_socket;
    struct event  *ev_engine;
    struct event  *ev_timeout;
    uint64_t       send_offset;
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

void xqc_client_set_event_timer(void *timer, xqc_msec_t wake_after)
{
    printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add((struct event *) timer, &tv);

}

int save_session_cb( char * data, size_t data_len, void *user_data){
    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _session_cb error\n");
        return -1;
    }
    fclose(fp);
    return 0;
}


int save_tp_cb(char * data, size_t data_len, void * user_data){
    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _tp_cb error\n");
        return -1;
    }
    fclose(fp);
    return 0;
}

void xqc_client_save_token(const unsigned char *token, unsigned token_len)
{
    int fd = open("./xqc_token",O_TRUNC|O_CREAT|O_WRONLY, S_IRWXU);
    if (fd < 0) {
        printf("save token error %s\n", strerror(errno));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(errno));
        return;
    }
}

int xqc_client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open("./xqc_token", O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(errno));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    printf("read token size %lld\n", n);
    printf("0x%x\n", token[0]);
    return n;
}

ssize_t xqc_client_write_socket(void *user, unsigned char *buf, size_t size)
{
    client_ctx_t *ctx = (client_ctx_t *) user;
    ssize_t res;
    int fd = ctx->my_conn->fd;
    printf("xqc_client_write_socket size=%zd, now=%llu\n",size, now());
    do {
        res = write(fd, buf, size);
        printf("xqc_client_write_socket %zd %s\n", res, strerror(errno));
    } while ((res < 0) && (errno == EINTR));
    return res;
}

static int xqc_client_create_socket(const char *addr, unsigned int port)
{
    int fd;
    struct sockaddr_in *saddr = &ctx.my_conn->peer_addr;
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

    if (connect(fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }

    socklen_t tmp = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&ctx.my_conn->local_addr, &tmp);

    printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx.my_conn->peer_addr.sin_addr), ntohs(ctx.my_conn->peer_addr.sin_port));
    printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx.my_conn->local_addr.sin_addr), ntohs(ctx.my_conn->local_addr.sin_port));



    return fd;

  err:
    close(fd);
    return -1;
}
int xqc_client_write_notify(xqc_stream_t *stream, void *user_data);

int xqc_client_conn_create_notify(xqc_cid_t *cid, void *user_data) {
    DEBUG;

    client_ctx_t *ctx = (client_ctx_t *) user_data;

    return 0;
}

int xqc_client_conn_close_notify(xqc_cid_t *cid, void *user_data) {
    DEBUG;

    client_ctx_t *ctx = (client_ctx_t *) user_data;

    return 0;
}

int xqc_client_write_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    int ret = 0;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[5000] = {0};
    ret = xqc_stream_send(stream, buff + ctx->send_offset, sizeof(buff) - ctx->send_offset, 1);
    if (ret < 0) {
        printf("xqc_stream_send error %d\n", ret);
    } else {
        ctx->send_offset += ret;
        printf("xqc_stream_send offset=%lld\n", ctx->send_offset);
    }
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


void
xqc_client_write_handler(client_ctx_t *ctx)
{
    DEBUG
    xqc_conn_write_handler(ctx->engine, &ctx->my_conn->cid);
}


void
xqc_client_read_handler(client_ctx_t *ctx)
{
    DEBUG

    ssize_t recv_size = 0;
    uint64_t recv_time = now();

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

    printf("xqc_client_read_handler recv_size=%zd, recv_time=%llu\n",recv_size, recv_time);
    /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->my_conn->peer_addr.sin_addr), ntohs(ctx->my_conn->peer_addr.sin_port));
    printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->my_conn->local_addr.sin_addr), ntohs(ctx->my_conn->local_addr.sin_port));
*/
    if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                            (struct sockaddr *)(&ctx->my_conn->local_addr), ctx->my_conn->local_addrlen,
                            (struct sockaddr *)(&ctx->my_conn->peer_addr), ctx->my_conn->peer_addrlen,
                            (xqc_msec_t)recv_time, ctx) != 0)
    {
        printf("xqc_client_read_handler: packet process err\n");
        return;
    }

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


static void
xqc_client_engine_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timer_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timeout_callback now %llu\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;
    int rc;
    rc = xqc_conn_close(ctx->engine, &ctx->my_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }

    //event_base_loopbreak(eb);
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
int  early_data_cb(xqc_connection_t *conn, int flag){

    if(flag == 0){
        printf(".....................early data reject\n");
    }else{
        printf("---------------------early data accept\n");
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


    memset(&ctx, 0, sizeof(ctx));

    char  session_path[256] = "./test_session";
    char  tp_path[256] = "./tp_localhost";
    char session_data[2048] = {0};
    //size_t session_data_len = read_file_data(session_data, sizeof(session_data), session_path );

    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;



    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);
    ctx.ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, &ctx);

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config);

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_client_conn_create_notify,
                    .conn_close_notify = xqc_client_conn_close_notify,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_client_write_notify,
                    .stream_read_notify = xqc_client_read_notify,
            },
            .write_socket = xqc_client_write_socket,
            //.cong_ctrl_callback = xqc_reno_cb,
            .cong_ctrl_callback = xqc_cubic_cb,
            .set_event_timer = xqc_client_set_event_timer,
            .save_token = xqc_client_save_token,
    };

    xqc_conn_settings_t conn_settings = {
            .pacing_on  =   1,
    };
    xqc_engine_init(ctx.engine, callback, conn_settings, ctx.ev_engine);

    ctx.my_conn = xqc_calloc(1, sizeof(user_conn_t));
    if (ctx.my_conn == NULL) {
        printf("xqc_malloc error\n");
        return 0;
    }

    ctx.my_conn->fd = xqc_client_create_socket(server_addr, server_port);
    if (ctx.my_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_socket = event_new(eb, ctx.my_conn->fd, EV_READ | EV_PERSIST, xqc_client_event_callback, &ctx);
    event_add(ctx.ev_socket, NULL);

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);
    if (token_len > 0) {
        ctx.my_conn->token = token;
        ctx.my_conn->token_len = token_len;
    }

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    event_add(ctx.ev_timeout, &tv);


    xqc_conn_ssl_config_t conn_ssl_config;

    memset(&conn_ssl_config, 0 ,sizeof(conn_ssl_config));
    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if(session_len < 0 || tp_len < 0){
        printf("sessoin data read error");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.tp_data  = NULL;
    }else{
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.tp_data = tp_data;
        conn_ssl_config.tp_data_len = tp_len;
    }



    xqc_cid_t *cid = xqc_connect(ctx.engine, &ctx, ctx.my_conn->token, ctx.my_conn->token_len, "127.0.0.1", 1, 0 ,&conn_ssl_config );
    if (cid == NULL) {
        printf("xqc_connect error\n");
        return 0;
    }
    memcpy(&ctx.my_conn->cid, cid, sizeof(*cid));

    xqc_connection_t * conn = xqc_engine_conns_hash_find(ctx.engine, cid, 's');
    //xqc_set_early_data_cb(conn, early_data_cb);
    xqc_set_save_session_cb(conn, (xqc_save_session_cb_t)save_session_cb, conn);
    xqc_set_save_tp_cb(conn, (xqc_save_tp_cb_t) save_tp_cb, conn);

    ctx.my_conn->stream = xqc_create_stream(ctx.engine, cid, &ctx);

    xqc_client_write_notify(ctx.my_conn->stream, &ctx);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
