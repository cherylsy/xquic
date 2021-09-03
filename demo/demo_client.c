#define _GNU_SOURCE

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
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
#include <netdb.h>
#include <string.h>
#include "common.h"



#define XQC_PACKET_TMP_BUF_LEN 1600
#define MAX_BUF_SIZE (100*1024*1024)

typedef enum alpn_type_s {
    ALPN_HQ,
    ALPN_H3,
} alpn_type_t;


#define MAX_HEADER 100

typedef struct user_conn_s user_conn_t;

typedef struct user_stream_s {
    user_conn_t        *user_conn;

    /* save file */
    char                file_name[RESOURCE_LEN];
    FILE               *recv_body_fp;

    /* stat for IO */
    size_t              send_body_len;
    size_t              recv_body_len;
    int                 recv_fin;
    xqc_msec_t          start_time;

    /* hq request content */
    xqc_stream_t       *stream;
    char*               send_buf;
    size_t              send_len;
    size_t              send_offset;

    /* h3 request content */
    xqc_h3_request_t   *h3_request;
    xqc_http_headers_t  h3_hdrs;
    uint8_t             hdr_sent;
} user_stream_t;


/**
 * ============================================================================
 * the network config definition section
 * network config is those arguments about socket connection
 * all configuration on network should be put under this section
 * ============================================================================
 */


typedef enum task_mode_s {
    MODE_SCMR,             /* send multi requests in single connection with multi streams */
    MODE_SCSR_SERIAL,      /* serially send multi requests in multi connections, with one request each connection */
    MODE_SCSR_CONCURRENT,  /* concurrently send multi requests in multi connections, with one request each connection */
} task_mode_t;


/* network arguments */
typedef struct net_config_s
{
    /* server addr info */
    struct sockaddr_in6 addr;
    int                 addr_len;
    char                server_addr[64];
    short               server_port;
    char                host[256];

    /* ipv4 or ipv6 */
    int     ipv6;

    /* congestion control algorithm */
    CC_TYPE cc;     /* congestion control algorithm */
    int     pacing; /* is pacing on */

    /* idle persist timeout */
    int     conn_timeout;

    task_mode_t mode;

} net_config_t;

/**
 * ============================================================================
 * the quic config definition section
 * quic config is those arguments about quic connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

/* definition for quic */
#define MAX_SESSION_TICKET_LEN      2048    /* session ticket len */
#define MAX_TRANSPORT_PARAMS_LEN    2048    /* transport parameter len */
#define XQC_MAX_TOKEN_LEN           256     /* token len */

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

typedef struct quic_config_s
{
    /* alpn protocol of client */
    alpn_type_t alpn_type;
    char alpn[16];

    /* 0-rtt config */
    int  st_len;                        /* session ticket len */
    char st[MAX_SESSION_TICKET_LEN];    /* session ticket buf */
    int  tp_len;                        /* transport params len */
    char tp[MAX_TRANSPORT_PARAMS_LEN];  /* transport params buf */
    int  token_len;                     /* token len */
    char token[XQC_MAX_TOKEN_LEN];      /* token buf */

    char *cipher_suits;                 /* cipher suits */

    uint8_t use_0rtt;                   /* 0-rtt switch, default turned off */
} quic_config_t;



/**
 * ============================================================================
 * the environment config definition section
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 * ============================================================================
 */

#define LOG_PATH "clog.log"
#define KEY_PATH "ckeys.log"
#define OUT_DIR  "."

/* environment config */
typedef struct env_config_s
{
    /* log path */
    char    log_path[256];
    int     log_level;

    /* out file */
    char    out_file_dir[256];

    /* key export */
    int     key_output_flag;
    char    key_out_path[256];

    /* life circle */
    int     life;
} env_config_t;


/**
 * ============================================================================
 * the request config definition section
 * all configuration on request should be put under this section
 * ============================================================================
 */

#define MAX_REQUEST_CNT 2048    /* client might deal MAX_REQUEST_CNT requests once */
#define MAX_REQUEST_LEN 256     /* the max length of a request */
#define g_host ""

/* args of one single request */
typedef struct request_s
{
    char            path[RESOURCE_LEN];         /* request path */
    char            scheme[8];                  /* request scheme, http/https */
    REQUEST_METHOD  method;
    char            auth[AUTHORITY_LEN];
    char            url[URL_LEN];               /* original url */
    // char            headers[MAX_HEADER][256];   /* field line of h3 */
} request_t;


/* request bundle args */
typedef struct requests_s {
    /* requests */
    char        urls[MAX_REQUEST_CNT * MAX_REQUEST_LEN];
    int         request_cnt;    /* requests cnt in urls */
    request_t   reqs[MAX_REQUEST_CNT];  // TODO: use pointer
} requests_t;


/**
 * ============================================================================
 * the client args definition section
 * client initial args
 * ============================================================================
 */
typedef struct client_args_s {
    /* network args */
    net_config_t net_cfg;

    /* quic args */
    quic_config_t quic_cfg;

    /* environment args */
    env_config_t env_cfg;

    /* request args */
    requests_t   req_cfg;
} client_args_t;


typedef enum task_status_s {
    TASK_STATUS_WAITTING,
    TASK_STATUS_RUNNING,
    TASK_STATUS_FINISHED,
    TASK_STATUS_FAILED,
} task_status_t;

typedef struct task_schedule_info_s
{
    task_status_t   status;         /* task status */
    int             req_create_cnt; /* streams created */
    int             req_sent_cnt;
    int             req_fin_cnt;    /* the req cnt which have received FIN */
    uint8_t         fin_flag;       /* all reqs finished, need close */
} task_schedule_info_t;


/* the task schedule info, used to mark the operation 
 * info of all requests, the client will exit when all
 * tasks are finished or closed
 */
typedef struct task_schedule_s
{
    int idx;                                /* the cnt of tasks that been running or have been ran */
    task_schedule_info_t *schedule_info;    /* the task status, 0: not executed; 1: suc; -1: failed */
} task_schedule_t;

/* task info structure. 
 * a task is strongly correlate to a net connection
 */
typedef struct task_s {
    int         task_idx;
    int         req_cnt;
    request_t   *reqs;      /* a task could contain multipule requests, which wil be sent  */
    user_conn_t *user_conn; /* user_conn handle */
} task_t;


typedef struct task_ctx_s {
    task_mode_t mode;   /* task mode */
    int         task_cnt;   /* total task cnt */
    task_t      *tasks;     /* task list */

    /* current task schedule info */
    task_schedule_t schedule;        /* current task index */
} task_ctx_t;



typedef struct client_ctx_s {
    /* xquic engine context */
    xqc_engine_t    *engine;

    /* libevent context */
    struct event    *ev_engine;
    struct event    *ev_task;
    struct event    *ev_kill;
    struct event_base *eb;  /* handle of libevent */

    /* log context */
    int             log_fd;
    char            log_path[256];

    /* key log context */
    int             keylog_fd;

    /* client context */
    client_args_t   *args;

    /* task schedule context */
    task_ctx_t      task_ctx;
} client_ctx_t;


typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr_in6 local_addr;
    socklen_t           local_addrlen;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    client_ctx_t       *ctx;
    uint64_t            last_sock_op_time;
    task_t             *task;
} user_conn_t;


/**
 * [return] 1: all req suc, task finished, 0: still got req underway
 */
void on_stream_fin(user_stream_t *user_stream)
{
    task_ctx_t *ctx = &user_stream->user_conn->ctx->task_ctx;
    int task_idx = user_stream->user_conn->task->task_idx;

    /* all reqs are finished, finish the task */
    if (++ctx->schedule.schedule_info[task_idx].req_fin_cnt
        == ctx->tasks[task_idx].req_cnt)
    {
        ctx->schedule.schedule_info[task_idx].fin_flag = 1;
    }
    printf("task[%d], fin_cnt: %d, fin_flag: %d\n", task_idx, 
        ctx->schedule.schedule_info[task_idx].req_fin_cnt, ctx->schedule.schedule_info[task_idx].fin_flag);
}

/* directly finish a task */
void on_task_finish(client_ctx_t *ctx, task_t *task)
{
    ctx->task_ctx.schedule.schedule_info[task->task_idx].status = TASK_STATUS_FINISHED;

    printf("task finished, total task_req_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, req_create_cnt: %d\n",
            task->req_cnt, 
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_fin_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_sent_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_create_cnt);
}

/* directly fail a task */
void on_task_fail(client_ctx_t *ctx, task_t *task)
{
    ctx->task_ctx.schedule.schedule_info[task->task_idx].status = TASK_STATUS_FAILED;

    printf("task failed, total task_req_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, req_create_cnt: %d\n",
            task->req_cnt, 
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_fin_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_sent_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_create_cnt);
}


static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}

void xqc_client_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

void save_session_cb(const char *data, size_t data_len, void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t*)conn_user_data;

    FILE * fp  = fopen(SESSION_TICKET_FILE, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void save_tp_cb(const char *data, size_t data_len, void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t*)conn_user_data;
    FILE * fp = fopen(TRANSPORT_PARAMS_FILE, "wb");
    if (NULL == fp) {
        printf("open file for transport parameter error\n");
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void xqc_client_save_token(const unsigned char *token, uint32_t token_len, void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t*)conn_user_data;

    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
    if (fd < 0) {
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        close(fd);
        return;
    }
    close(fd);
}

int xqc_client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}

int read_file_data(char *data, size_t data_len, char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size_t total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (total_len > data_len) {
        return -1;
    }

    size_t read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len) {
        return -1;
    }

    return read_len;
}

ssize_t
xqc_client_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t *)conn_user_data;
    ssize_t res = 0;
    do {
        errno = 0;
        res = sendto(user_conn->fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s, fd: %d, buf: %p, size: %Zu, server_addr: %s\n",
                res, strerror(errno), user_conn->fd, buf, size, user_conn->ctx->args->net_cfg.server_addr);
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
        user_conn->last_sock_op_time = now();
    } while ((res < 0) && (errno == EINTR));

    // usleep(200);
    return res;
}


ssize_t xqc_client_write_mmsg(void *user, struct iovec *msg_iov, unsigned int vlen,
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


static int xqc_client_create_socket(user_conn_t *user_conn, net_config_t* cfg)
{
    int fd = 0;
    struct sockaddr *addr = (struct sockaddr*)&cfg->addr;
    fd = socket(addr->sa_family, SOCK_DGRAM, 0);
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

    user_conn->last_sock_op_time = now();
    user_conn->local_addrlen = sizeof(struct sockaddr_in6);
    getsockname(user_conn->fd, (struct sockaddr*)&user_conn->local_addr, &user_conn->local_addrlen);

    return fd;

  err:
    close(fd);
    return -1;
}

int xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    printf("xqc_client_conn_create_notify, conn: %p, user_conn: %p\n", conn, user_data);
    user_conn_t *user_conn = (user_conn_t *)user_data;
    printf("xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    printf("xqc_client_conn_close_notify, conn: %p, user_conn: %p\n", conn, user_data);

    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, "
        "srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
        stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count,
        stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    on_task_finish(user_conn->ctx, user_conn->task);
    free(user_conn);
    return 0;
}

void xqc_client_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, 
    void *ping_user_data, void *conn_user_data)
{
    DEBUG;
    if (ping_user_data) {
        // printf("ping_id:%d\n", *(int *) ping_user_data);
    }
    return;
}

void xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn[%p] handshake finished\n", conn);
}


int client_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->start_time == 0) {
        user_stream->start_time = now();
    }

    int fin = 1;
    if (user_stream->send_offset < user_stream->send_len) {
        ret = xqc_stream_send(stream, user_stream->send_buf + user_stream->send_offset,
                              user_stream->send_len - user_stream->send_offset, fin);
        if (ret < 0) {
            switch (-ret)
            {
            case XQC_EAGAIN:
                return 0;
            
            default:
                printf("send stream failed, ret: %Zd\n", ret);
                return -1;
            }

        } else {
            user_stream->send_offset += ret;
            user_stream->send_body_len += ret;
        }
    }

    return ret;
}

int client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    if (user_stream->send_len > user_stream->send_offset)
    {
        ret = client_stream_send(user_stream->stream, user_stream);
        // printf("client_stream_write_notify, user_stream[%p] send_cnt: %d\n", user_stream, ret);
        if (ret == user_stream->send_len) {
            user_stream->user_conn->ctx->task_ctx.schedule.schedule_info->req_sent_cnt++;
        }
    }
    return 0;
}

int client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    char buff[4096] = {0};
    size_t buff_size = 4096;

    ssize_t read = 0;
    ssize_t read_sum = 0;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        int nwrite = fwrite(buff, 1, read, user_stream->recv_body_fp);
        if (nwrite != read) {
            printf("fwrite error\n");
            return -1;
        }
        fflush(user_stream->recv_body_fp);

        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_msec_t now_us = now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> user_stream[%p], req: %s, send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (user_stream->send_body_len + user_stream->recv_body_len)*1000/(now_us - user_stream->start_time),
               user_stream, user_stream->file_name, user_stream->send_body_len, user_stream->recv_body_len);

        /* close file */
        fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = NULL;

        on_stream_fin(user_stream);
    }
    return 0;
}


int client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    printf("client_stream_close_notify, stream: %p, user_conn: %p\n", stream, user_data);

    user_stream_t *user_stream = (user_stream_t*)user_data;

    /* task schedule */
    // on_stream_fin(user_stream);

    free(user_stream->send_buf);
    free(user_stream);
    return 0;
}

ssize_t client_request_send(user_stream_t *user_stream)
{
    ssize_t ret = 0;
    if (!user_stream->hdr_sent)
    {
        if (user_stream->start_time == 0) {
            user_stream->start_time = now();
        }

        ret = xqc_h3_request_send_headers(user_stream->h3_request, &user_stream->h3_hdrs, 1);
        if (ret < 0) {
            printf("client_request_send error %zd\n", ret);
        } else {
            printf("client_request_send success size=%zd\n", ret);
            user_stream->hdr_sent = 1;
        }
    }

    return ret;
}

int client_h3_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    // printf("client_h3_request_create_notify, h3_request: %p, user_stream: %p\n", h3_request, user_stream);
    ret = client_request_send(user_stream);
    //printf("client_h3_request_write_notify user_data: %p, send request ret: %Zd\n", user_data, ret);

    return 0;
}

int client_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    // printf("client_h3_request_create_notify, h3_request: %p, user_stream: %p\n", h3_request, user_stream);
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

    ssize_t read = 0;
    ssize_t read_sum = 0;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return 0;
        }

        if (fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        fflush(user_stream->recv_body_fp);

        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_msec_t now_us = now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size) * 1000 / (now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size);

        // on_stream_fin(user_stream);
    }
    return 0;
}

int client_h3_request_create_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    //"client_h3_request_create_notify, h3_request: %p, user_data: %p\n", h3_request, user_data);

    return 0;
}

int client_h3_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;
    user_conn_t *user_conn = user_stream->user_conn;

    /* task schedule */
    on_stream_fin(user_stream);

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, recv_fin:%d, err:%d\n",
           stats.send_body_size, stats.recv_body_size,
           stats.send_header_size, stats.recv_header_size,
           user_stream->recv_fin, stats.stream_err);

    free(user_stream);
    return 0;
}


/******************************************************************************
 *                     start of socket callback functions                     *
 ******************************************************************************/

void
client_socket_write_handler(user_conn_t *user_conn)
{
    DEBUG;
    // xqc_conn_continue_send(ctx.engine, &user_conn->cid);
}

void
client_socket_read_handler(user_conn_t *user_conn)
{
    DEBUG;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;
    struct sockaddr addr;
    socklen_t addr_len;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    do {
        recv_size = recvfrom(user_conn->fd, packet_buf, sizeof(packet_buf), 0,
                            (struct sockaddr *)&addr, &addr_len);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }

        if (recv_size <= 0) {
            break;
        }

        recv_sum += recv_size;
        uint64_t recv_time = now();
        user_conn->last_sock_op_time = recv_time;
        if (xqc_engine_packet_process(user_conn->ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *)(&user_conn->local_addr),
                                      user_conn->local_addrlen, (struct sockaddr *)(&addr), addr_len,
                                      (xqc_msec_t)recv_time, user_conn) != 0)
        {
            return;
        }
    } while (recv_size > 0);

finish_recv:
    xqc_engine_finish_recv(user_conn->ctx->engine);
}


static void
client_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        client_socket_write_handler(user_conn);
    } else if (what & EV_READ) {
        client_socket_read_handler(user_conn);
    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}


/******************************************************************************
 *                     start of engine callback functions                     *
 ******************************************************************************/

static void
client_engine_callback(int fd, short what, void *arg)
{
    // printf("timer wakeup now:%"PRIu64"\n", now());
    client_ctx_t *ctx = (client_ctx_t *) arg;
    xqc_engine_main_logic(ctx->engine);
}


static void
client_idle_callback(int fd, short what, void *arg)
{
    int rc = 0;
    user_conn_t *user_conn = (user_conn_t *) arg;
    if (now() - user_conn->last_sock_op_time < (uint64_t)user_conn->ctx->args->net_cfg.conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = user_conn->ctx->args->net_cfg.conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);

    } else {
        rc = xqc_conn_close(user_conn->ctx->engine, &user_conn->cid);
        if (rc) {
            printf("xqc_conn_close error\n");
            return;
        }

        printf("socket idle timeout, task failed, total task_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, req_create_cnt: %d\n",
               user_conn->ctx->task_ctx.tasks[user_conn->task->task_idx].req_cnt, 
               user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_fin_cnt, 
               user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_sent_cnt,
               user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
        on_task_fail(user_conn->ctx, user_conn->task);
    }
}

/******************************************************************************
 *                       start of log callback functions                      *
 ******************************************************************************/

#if 0
int client_open_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    ctx->log_fd = open(ctx->log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int client_close_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}
#endif

int client_open_log_file(client_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int client_close_log_file(client_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

void client_write_log_file(const void *buf, size_t size, void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    //printf("%s",(char*)buf);
    write(ctx->log_fd, buf, size);
    write(ctx->log_fd, line_break, 1);
}


/******************************************************************************
 *                       start of client keylog functions                     *
 ******************************************************************************/
int client_open_keylog_file(client_ctx_t *ctx)
{
    ctx->keylog_fd = open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;    
}

int client_close_keylog_file(client_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }
    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}

void xqc_keylog_cb(const char *line, void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    write(ctx->keylog_fd, line, strlen(line));
    write(ctx->keylog_fd, "\n", 1);
}


/******************************************************************************
 *                        start of client init functions                      *
 ******************************************************************************/

void init_0rtt(client_args_t *args)
{
    /* read session ticket */
    int ret = read_file_data(args->quic_cfg.st,
        MAX_SESSION_TICKET_LEN, SESSION_TICKET_FILE);
    args->quic_cfg.st_len = ret > 0 ? ret : 0;

    /* read transport params */
    ret = read_file_data(args->quic_cfg.tp, 
        MAX_TRANSPORT_PARAMS_LEN, TRANSPORT_PARAMS_FILE);
    args->quic_cfg.tp_len = ret > 0 ? ret : 0;

    /* read token */
    ret = xqc_client_read_token(
        args->quic_cfg.token, XQC_MAX_TOKEN_LEN);
    args->quic_cfg.token_len = ret > 0 ? ret : 0;
}


void init_engine_ssl_config(xqc_engine_ssl_config_t* cfg, client_args_t *args)
{
    memset(cfg, 0 ,sizeof(xqc_engine_ssl_config_t));
    if (args->quic_cfg.cipher_suits) {
        cfg->ciphers = args->quic_cfg.cipher_suits;

    } else {
        cfg->ciphers = XQC_TLS_CIPHERS;
    }

    cfg->groups = XQC_TLS_GROUPS;
}

void init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, client_args_t *args)
{
    memset(conn_ssl_config, 0, sizeof(xqc_conn_ssl_config_t));

    /* set alpn */
    // TODO: alpn选择
    // conn_ssl_config->alpn = args->quic_cfg.alpn;

    /* set session ticket and transport parameter args */
    if (args->quic_cfg.st_len < 0 || args->quic_cfg.tp_len < 0) {
        conn_ssl_config->session_ticket_data = NULL;
        conn_ssl_config->transport_parameter_data = NULL;

    } else {
        conn_ssl_config->session_ticket_data = args->quic_cfg.st;
        conn_ssl_config->session_ticket_len = args->quic_cfg.st_len;
        conn_ssl_config->transport_parameter_data = args->quic_cfg.tp;
        conn_ssl_config->transport_parameter_data_len = args->quic_cfg.tp_len;
    }
}

void init_conneciton_settings(xqc_conn_settings_t* settings, client_args_t *args)
{
    xqc_cong_ctrl_callback_t cong_ctrl;
    switch (args->net_cfg.cc)
    {
    case CC_TYPE_BBR:
        cong_ctrl = xqc_bbr_cb;
        break;
    
    case CC_TYPE_CUBIC:
        cong_ctrl = xqc_reno_cb;
        break;

    case CC_TYPE_RENO:
        cong_ctrl = xqc_cubic_cb;
        break;

    default:
        break;
    }

    xqc_conn_settings_t cs = {
        .pacing_on  = args->net_cfg.pacing,
        .ping_on    = 0,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  = {
            .customize_on = 1,
            .init_cwnd = 32,
        },
        .so_sndbuf  = 1024*1024,
        .proto_version = XQC_VERSION_V1,
        .spurious_loss_detect_on = 1,
    };
    *settings = cs;
}

/* set client args to default values */
void init_client_args(client_args_t *args)
{
    memset(args, 0, sizeof(client_args_t));

    /* net cfg */
    args->net_cfg.conn_timeout = 30;
    strcpy(args->net_cfg.server_addr, "127.0.0.1");
    args->net_cfg.server_port = 8443;

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strcpy(args->env_cfg.log_path, LOG_PATH);
    strcpy(args->env_cfg.out_file_dir, OUT_DIR);

    /* quic cfg */
    args->quic_cfg.alpn_type = ALPN_HQ;
    strcpy(args->quic_cfg.alpn, "hq-interop");
}

void parse_server_addr(char *url, net_config_t *cfg)
{
    /* get hostname and port */
    char s_port[16] = {0};
    sscanf(url,"%*[^://]://%[^:]:%[^/]", cfg->host, s_port);

    /* parse port */
    cfg->server_port = atoi(s_port);

    /* set hint for hostname resolve */
    struct addrinfo hints = {0};
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    /* resolve server's ip from hostname */
    struct addrinfo *result = NULL;
    int rv = getaddrinfo(cfg->host, s_port, &hints, &result);
    if (rv != 0) {
        printf("get addr info from hostname: %s\n", gai_strerror(rv));
    }
    memcpy(&cfg->addr, result->ai_addr, result->ai_addrlen);
    cfg->addr_len = result->ai_addrlen;

    /* convert to string. */
    if (result->ai_family == AF_INET6) {
        inet_ntop(result->ai_family, &(((struct sockaddr_in6*)result->ai_addr)->sin6_addr),
            cfg->server_addr, sizeof(cfg->server_addr));
    } else {
        inet_ntop(result->ai_family, &(((struct sockaddr_in*)result->ai_addr)->sin_addr),
            cfg->server_addr, sizeof(cfg->server_addr));
    }
    
    printf("server[%s] addr: %s:%d.\n", cfg->host, cfg->server_addr, cfg->server_port);
}

void parse_urls(char *urls, client_args_t *args)
{
    /* split urls */
    int cnt = 0;
    static char* separator = " ";
    char *token = strtok(urls, separator);
    while (token != NULL) {
        if (token) {
            strcpy(args->req_cfg.reqs[cnt].url, token);
            sscanf(token,"%[^://]://%[^/]%s", args->req_cfg.reqs[cnt].scheme,
                args->req_cfg.reqs[cnt].auth, args->req_cfg.reqs[cnt].path);
        }
        cnt++;
        token = strtok(NULL, separator);
    }
    args->req_cfg.request_cnt = cnt;

    /* parse the server addr */
    if (args->req_cfg.request_cnt > 0) {
        parse_server_addr(args->req_cfg.reqs[0].url, &args->net_cfg);
    }
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
        "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic\n"
        "   -C    Pacing on.\n"
        "   -t    Connection timeout. Default 3 seconds.\n"
        "   -S    cipher suites\n"
        "   -0    use 0-RTT\n"
        "   -A    alpn selection: h3/hq\n"
        "   -D    save request body directory\n"
        "   -l    Log level. e:error d:debug.\n"
        "   -L    xuqic log directory.\n"
        "   -U    Url. \n"
        "   -k    key out path\n"
        "   -K    Client's life circle time\n"
        , prog);
}


void parse_args(int argc, char *argv[], client_args_t *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, "a:p:c:Ct:S:0m:A:D:l:L:k:K:U:")) != -1) {
        switch(ch)
        {
        /* server ip */
        case 'a':
            printf("option addr :%s\n", optarg);
            snprintf(args->net_cfg.server_addr, sizeof(args->net_cfg.server_addr), optarg);
            break;

        /* server port */
        case 'p':
            printf("option port :%s\n", optarg);
            args->net_cfg.server_port = atoi(optarg);
            break;

        /* congestion control */
        case 'c':
            printf("option cong_ctl :%s\n", optarg);
            /* r:reno b:bbr c:cubic */
            switch (*optarg)
            {
            case 'b':
                args->net_cfg.cc = CC_TYPE_BBR;
                break;
            case 'c':
                args->net_cfg.cc = CC_TYPE_CUBIC;
                break;
            case 'r':
                args->net_cfg.cc = CC_TYPE_RENO;
                break;
            default:
                break;
            }
            break;

        /* pacing */
        case 'C':
            printf("option pacing :%s\n", "on");
            args->net_cfg.pacing = 1;
            break;

        /* idle persist timeout */
        case 't':
            printf("option connection timeout :%s\n", optarg);
            args->net_cfg.conn_timeout = atoi(optarg);
            break;

        /* ssl cipher suits */
        case 'S':
            printf("option cipher suits: %s\n", optarg);
            args->quic_cfg.cipher_suits = optarg;
            break;

        /* 0rtt option */
        case '0':
            printf("option 0rtt\n");
            args->quic_cfg.use_0rtt = 1;
            break;

        /* multi connections */
        case 'm':
            printf("option multi connection: on\n");
            switch (atoi(optarg))
            {
            case 0:
                args->net_cfg.mode = MODE_SCMR;
                break;
            case 1:
                args->net_cfg.mode = MODE_SCSR_SERIAL;
                break;
            case 2:
                args->net_cfg.mode = MODE_SCSR_CONCURRENT;
            default:
                break;
            }
            break;

        /* alpn */
        case 'A':
            printf("option set ALPN[%s]\n", optarg);
            if (strcmp(optarg, "h3") == 0) {
                args->quic_cfg.alpn_type = ALPN_H3;
                strncpy(args->quic_cfg.alpn, "h3", 3);

            } else if (strcmp(optarg, "hq") == 0) {
                args->quic_cfg.alpn_type = ALPN_HQ;
                strncpy(args->quic_cfg.alpn, "hq-interop", 11);
            }

            break;

        /* out file directory */
        case 'D':
            printf("option save body dir: %s\n", optarg);
            strncpy(args->env_cfg.out_file_dir, optarg, sizeof(args->env_cfg.out_file_dir));
            break;

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            /* e:error d:debug */
            args->env_cfg.log_level = optarg[0];
            break;

        /* log directory */
        case 'L':
            printf("option log directory :%s\n", optarg);
            strncpy(args->env_cfg.log_path, optarg, sizeof(args->env_cfg.log_path));
            break;

        /* key out path */
        case 'k':
            printf("key output file: %s\n", optarg);
            args->env_cfg.key_output_flag = 1;
            strncpy(args->env_cfg.key_out_path, optarg, sizeof(args->env_cfg.key_out_path));
            break;

        /* client life time circle */
        case 'K':
            printf("client life circle time: %s\n", optarg);
            args->env_cfg.life = atoi(optarg);
            break;

        /* request urls */
        case 'U': // 请求URL，不再带入地址，从请求中进行解析
            printf("option url only:%s\n", optarg);
            parse_urls(optarg, args);
            break;

        default:
            printf("other option :%c\n", ch);
            usage(argc, argv);
            exit(0);
        }
    }
}

#define MAX_REQ_BUF_LEN 1500
int format_hq_req(char* buf, int len, request_t* req)
{
    return snprintf(buf, len, "%s %s\r\n", method_s[req->method], req->path);
}

int send_hq_req(user_conn_t *user_conn, user_stream_t *user_stream, request_t *req)
{
    /* create stream */
    user_stream->stream = xqc_stream_create(user_conn->ctx->engine, &user_conn->cid, user_stream);
    if (user_stream->stream == NULL) {
        // printf("user_conn: %p, create stream failed, will try later\n", user_stream);
        return -1;
    }
    /* prepare stream data, which will be sent on callback */
    user_stream->send_buf = calloc(1, MAX_REQ_BUF_LEN);
    user_stream->send_len = format_hq_req(user_stream->send_buf, MAX_REQ_BUF_LEN, req);
    int ret = client_stream_send(user_stream->stream, user_stream);
    // printf("client_stream_write_notify, user_stream[%p] send_cnt: %d\n", user_stream, ret);
    return 0;
}


int format_h3_req(xqc_http_header_t *headers, size_t sz, request_t* req)
{
    /* response header buf list */
    xqc_http_header_t req_hdr[] = {
        {
            .name = {.iov_base = ":method", .iov_len = 7},
            .value = {.iov_base = method_s[req->method], .iov_len = strlen(method_s[req->method])},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":scheme", .iov_len = 7},
            .value = {.iov_base = req->scheme, .iov_len = strlen(req->scheme)},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":path", .iov_len = 5},
            .value = {.iov_base = req->path, .iov_len = strlen(req->path)},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":authority", .iov_len = 10},
            .value = {.iov_base = req->auth, .iov_len = strlen(req->auth)},
            .flags = 0,
        }
    };

    size_t req_sz = sizeof(req_hdr) / sizeof(req_hdr[0]);
    if (sz < req_sz) {
        return -1;
    }

    for (size_t i = 0; i < req_sz; i++) {
        headers[i] = req_hdr[i];
    }

    return req_sz;    
}

int send_h3_req(user_conn_t *user_conn, user_stream_t *user_stream, request_t *req)
{
    user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid, user_stream);
    if (user_stream->h3_request == NULL) {
        printf("xqc_h3_request_create error\n");
        return -1;
    }

    // char req_buf[MAX_REQ_BUF_LEN] = {0};
    xqc_http_header_t header[H3_HDR_CNT];
    int hdr_cnt = format_h3_req(header, H3_HDR_CNT, req);
    if (hdr_cnt > 0) {
        user_stream->h3_hdrs.headers = header;
        user_stream->h3_hdrs.count = hdr_cnt;
        client_request_send(user_stream);
    }
    return 0;
}

void open_file(user_stream_t *user_stream, const char* save_path, const char *req_path)
{
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", save_path, req_path);
    user_stream->recv_body_fp = fopen(file_path, "wb");
    if (NULL == user_stream->recv_body_fp) {
        printf("open file[%s] error\n", file_path);
    }
    printf("open file[%s] suc\n", file_path);
}

void on_task_req_sent(client_ctx_t *ctx, int task_id)
{
    ctx->task_ctx.schedule.schedule_info[task_id].req_create_cnt++;
}

void send_requests(user_conn_t *user_conn, client_args_t *args, request_t *reqs, int req_cnt)
{
    DEBUG;
    for (int i = 0; i < req_cnt; i++) {
        /* user handle of stream */
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        // printf("   .. user_stream: %p\n", user_stream);

        /* open save file */
        open_file(user_stream, args->env_cfg.out_file_dir, reqs[i].path);
        strcpy(user_stream->file_name, reqs[i].path);

        /* send request */
        if (args->quic_cfg.alpn_type == ALPN_HQ) {
            if (send_hq_req(user_conn, user_stream, reqs + i) < 0) {
                printf("send hq req blocked, will try later, total sent_cnt: %d\n", 
                    user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
                free(user_stream);
                return;
            }

        } else if (args->quic_cfg.alpn_type == ALPN_H3) {
            if (send_h3_req(user_conn, user_stream, reqs + i) < 0) {
                printf("send h3 req blocked, will try later, total sent_cnt: %d\n", 
                    user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
                free(user_stream);
                return;
            }
        }

        on_task_req_sent(user_conn->ctx, user_conn->task->task_idx);
    }
}

void continue_send_reqs(user_conn_t *user_conn)
{
    client_ctx_t *ctx = user_conn->ctx;
    int task_idx = user_conn->task->task_idx;
    int req_create_cnt = ctx->task_ctx.schedule.schedule_info[task_idx].req_create_cnt;
    int req_cnt = user_conn->task->req_cnt - req_create_cnt;
    if (req_cnt > 0) {
        request_t *reqs = user_conn->task->reqs + req_create_cnt;
        send_requests(user_conn, ctx->args, reqs, req_cnt);
    }
}

#if 0
void on_max_streams(xqc_connection_t *conn, void *user_data, uint64_t max_streams, int type)
{
    printf("--- on_max_streams: %Zu, type: %d, continue to send\n", max_streams, type);
    user_conn_t *user_conn = (user_conn_t *)user_data;
    continue_send_reqs(user_conn);
}
#endif

/******************************************************************************
 *                     start of http/3 callback functions                     *
 ******************************************************************************/

int client_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    // printf("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(h3_conn));
    return 0;
}

int client_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" "
           "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count, stats.lost_count,
           stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err,
           stats.ack_info);

    on_task_finish(user_conn->ctx, user_conn->task);
    free(user_conn);
    return 0;
}

void client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);
}

void client_h3_conn_ping_acked_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *ping_user_data, void *user_data)
{
    if (ping_user_data) {
        // printf("ping_id:%d\n", *(int *) ping_user_data);
    }
}

#if 0
void client_h3_conn_max_streams(xqc_h3_conn_t *conn, void *user_data, uint64_t max_streams, int type)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *)user_data;
    continue_send_reqs(user_conn);
}
#endif


void init_callback(xqc_engine_callback_t *cb, client_args_t* args)
{
    static xqc_engine_callback_t callback = {
        /* HTTP3不用设置这个回调 */
        .conn_callbacks = {
            .conn_create_notify = xqc_client_conn_create_notify,
            .conn_close_notify = xqc_client_conn_close_notify,
            .conn_handshake_finished = xqc_client_conn_handshake_finished,
            .conn_ping_acked = xqc_client_conn_ping_acked_notify,
//            .conn_max_streams = on_max_streams,
        },
        .h3_conn_callbacks = {
            .h3_conn_create_notify = client_h3_conn_create_notify, /* 连接创建完成后回调,用户可以创建自己的连接上下文 */
            .h3_conn_close_notify = client_h3_conn_close_notify, /* 连接关闭时回调,用户可以回收资源 */
            .h3_conn_handshake_finished = client_h3_conn_handshake_finished, /* 握手完成时回调 */
            .h3_conn_ping_acked = client_h3_conn_ping_acked_notify,
//            .h3_conn_max_streams = client_h3_conn_max_streams,
        },
        /* 仅使用传输层时实现 */
        .stream_callbacks = {
            .stream_write_notify = client_stream_write_notify, /* 可写时回调，用户可以继续调用写接口 */
            .stream_read_notify = client_stream_read_notify, /* 可读时回调，用户可以继续调用读接口 */
            .stream_close_notify = client_stream_close_notify, /* 关闭时回调，用户可以回收资源 */
        },
        /* 使用应用层时实现 */
        .h3_request_callbacks = {
            .h3_request_write_notify = client_h3_request_write_notify, /* 可写时回调，用户可以继续调用写接口 */
            .h3_request_read_notify = client_h3_request_read_notify, /* 可读时回调，用户可以继续调用读接口 */
            .h3_request_create_notify = client_h3_request_create_notify,
            .h3_request_close_notify = client_h3_request_close_notify, /* 关闭时回调，用户可以回收资源 */
        },
        .write_socket = xqc_client_write_socket, /* 用户实现socket写接口 */
        .set_event_timer = xqc_client_set_event_timer, /* 设置定时器，定时器到期时调用xqc_engine_main_logic */
        .save_token = xqc_client_save_token, /* 保存token到本地，connect时带上 */
        .log_callbacks = {
            .xqc_log_write_err = client_write_log_file,
            .xqc_log_write_stat = client_write_log_file
        },
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
        .keylog_cb = xqc_keylog_cb,
    };

    *cb = callback;
}


int init_xquic_engine(client_ctx_t *pctx, client_args_t *args)
{
    /* init engine ssl config */
    xqc_engine_ssl_config_t engine_ssl_config;
    init_engine_ssl_config(&engine_ssl_config, args);

    /* init engine callbacks */
    xqc_engine_callback_t callback;
    init_callback(&callback, args);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }

    switch (args->env_cfg.log_level)
    {
    case 'd':
        config.cfg_log_level = XQC_LOG_DEBUG;
        break;
    case 'i':
        config.cfg_log_level = XQC_LOG_INFO;
        break;
    case 'w':
        config.cfg_log_level = XQC_LOG_WARN;
        break;
    case 'e':
        config.cfg_log_level = XQC_LOG_ERROR;
        break;
    default:
        config.cfg_log_level = XQC_LOG_DEBUG;
        break;
    }

    pctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, 
                                     &engine_ssl_config, &callback, pctx);
    if (pctx->engine == NULL) {
        printf("xqc_engine_create error\n");
        return XQC_ERROR;
    }

    return XQC_OK;
}

int init_xquic_connection(user_conn_t *user_conn, client_args_t *args)
{
    /* load 0-rtt args before create connection */
    init_0rtt(args);

    /* init connection settings */
    xqc_conn_settings_t conn_settings;
    init_conneciton_settings(&conn_settings, args);

    xqc_conn_ssl_config_t conn_ssl_config;
    init_conn_ssl_config(&conn_ssl_config, args);

    const xqc_cid_t *cid = NULL;
    if (args->quic_cfg.alpn_type == ALPN_H3) {
        cid = xqc_h3_connect(user_conn->ctx->engine, &conn_settings, args->quic_cfg.token,
                             args->quic_cfg.token_len, args->net_cfg.host, 0, &conn_ssl_config, 
                             (struct sockaddr*)&args->net_cfg.addr, args->net_cfg.addr_len, user_conn);

    } else {
        cid = xqc_hq_connect(user_conn->ctx->engine, &conn_settings, args->quic_cfg.token,
                             args->quic_cfg.token_len, args->net_cfg.host, 0, &conn_ssl_config, 
                             (struct sockaddr*)&args->net_cfg.addr, args->net_cfg.addr_len, user_conn);
    }

    if (cid == NULL) {
        xqc_engine_destroy(user_conn->ctx->engine);
        return XQC_OK;
    }
    /* cid要copy到自己的内存空间，防止内部cid被释放导致crash */
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));
    return XQC_OK;
}


uint8_t is_0rtt_compliant(client_args_t *args)
{
    return (args->quic_cfg.use_0rtt
        && args->quic_cfg.st_len > 0 && args->quic_cfg.tp_len > 0);
}

void start_xquic_client(user_conn_t *user_conn, client_args_t *args, request_t *reqs, int req_cnt)
{
    if (XQC_OK != init_xquic_connection(user_conn, args)) {
        printf("|start_xquic_client FAILED|\n");
        return;
    }

#if 0
    if (is_0rtt_compliant(args)) {
        printf("0rtt compliant, send 0rtt streams\n");
        send_requests(user_conn, args, reqs, req_cnt);
    }
#endif

    /* TODO: fix MAX_STREAMS bug */
    send_requests(user_conn, args, reqs, req_cnt);
}

void init_client_ctx(client_ctx_t *pctx, client_args_t *args)
{
    strcpy(pctx->log_path, args->env_cfg.log_path);
    pctx->args = args;
    client_open_log_file(pctx);
    client_open_keylog_file(pctx);
}


int all_tasks_finished(client_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {
        if (ctx->task_ctx.schedule.schedule_info[i].status <= TASK_STATUS_RUNNING) {
            return 0;
        }
    }
    return 1;
}


/* 在没有任务执行的情况下，获取一个等待执行的任务 */
int get_idle_waiting_task(client_ctx_t *ctx)
{
    int waiting_idx = -1;
    int idle_flag = 1;
    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {
        /* if any task is running, break loop, and return no task */
        if (ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_RUNNING) {
            idle_flag = 0;
            break;
        }

        if (waiting_idx < 0 && ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_WAITTING) {
            /* mark the first idle task */
            waiting_idx = i;
        }

    }

    return idle_flag ? waiting_idx : -1;
}


/* create one connection, send multi reqs in multi streams */
int handle_task(client_ctx_t *ctx, task_t *task)
{
    DEBUG;
    /* create socket and connection callback user data */
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    user_conn->ctx = ctx;
    user_conn->task = task;
    // printf(".. user_conn: %p, ctx: %p\n", user_conn, ctx);
    user_conn->fd = xqc_client_create_socket(user_conn, &ctx->args->net_cfg);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return -1;
    }

    /* socket event */
    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST,
                                     client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    /* xquic timer */
    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, client_idle_callback, user_conn);
    struct timeval tv;
    tv.tv_sec = ctx->args->net_cfg.conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    /* start client */
    start_xquic_client(user_conn, ctx->args, task->reqs, task->req_cnt);

    task->user_conn = user_conn;
    return 0;
}

int close_task(client_ctx_t *ctx, task_t *task)
{
    user_conn_t *user_conn = task->user_conn;

    /* close xquic conn */
    xqc_conn_close(ctx->engine, &user_conn->cid);

    /* remove task event handle */
    event_del(user_conn->ev_socket);
    event_del(user_conn->ev_timeout);

    /* close socket */
    close(user_conn->fd);
    return 0;
}



static struct timeval tv_task_schedule = {0, 100};

/* the task schedule timer callback, will break the main event loop
 * when all tasks are responsed or closed
 * under multi-connction mode, if previous task has finished, will
 * start a new connection and task.
 */
static void task_schedule_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t*)arg;
    uint8_t all_task_fin_flag = 1;
    uint8_t idle_flag = 1;
    int idle_waiting_task_id = -1;

    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {
        /* if task finished, close task */
        if (ctx->task_ctx.schedule.schedule_info[i].fin_flag) {
            close_task(ctx, ctx->task_ctx.tasks + i);
            ctx->task_ctx.schedule.schedule_info[i].fin_flag = 0;
        }

        /* check if all tasks are finished */
        if (ctx->task_ctx.schedule.schedule_info[i].status <= TASK_STATUS_RUNNING) {
            all_task_fin_flag = 0;
        }

        /* record the first waiting task */
        if (idle_waiting_task_id == -1
            && ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_WAITTING)
        {
            idle_waiting_task_id = i;
        }
    }

    if (all_task_fin_flag) {
        printf("all tasks are finished, will break loop and exit\n\n");
        event_base_loopbreak(ctx->eb);
        return;
    }

    /* if idle and got a waiting task, run the task */
    if (idle_flag && idle_waiting_task_id >= 0) {
        /* handle task and set status to RUNNING */
        int ret = handle_task(ctx, ctx->task_ctx.tasks + idle_waiting_task_id);
        if (0 == ret) {
            ctx->task_ctx.schedule.schedule_info[idle_waiting_task_id].status = TASK_STATUS_RUNNING;

        } else {
            ctx->task_ctx.schedule.schedule_info[idle_waiting_task_id].status = TASK_STATUS_FAILED;
        }
    }

    /* start next round */ 
    event_add(ctx->ev_task, &tv_task_schedule);
}


void init_scmr(task_ctx_t *tctx, client_args_t *args)
{
    tctx->task_cnt = 1; /* one task, one connection, all requests */

    /* init task list */
    tctx->tasks = calloc(1, sizeof(task_t) * 1);
    tctx->tasks->req_cnt = args->req_cfg.request_cnt;
    tctx->tasks->reqs = args->req_cfg.reqs;

    /* init schedule */
    tctx->schedule.schedule_info = calloc(1, sizeof(task_schedule_info_t) * 1);
}


void init_scsr(task_ctx_t *tctx, client_args_t *args)
{
    tctx->task_cnt = args->req_cfg.request_cnt;

    /* init task list */
    tctx->tasks = calloc(1, sizeof(task_t) * tctx->task_cnt);
    for (int i = 0; i < tctx->task_cnt; i++) {
        tctx->tasks[i].task_idx = i;
        tctx->tasks[i].req_cnt = 1;
        tctx->tasks[i].reqs = (request_t*)args->req_cfg.reqs + i;
    }

    /* init schedule */
    tctx->schedule.schedule_info = calloc(1, sizeof(task_schedule_info_t) * tctx->task_cnt);
}


/* create task info according to args */
void init_tasks(client_ctx_t *ctx)
{
    ctx->task_ctx.mode = ctx->args->net_cfg.mode;
    switch (ctx->args->net_cfg.mode)
    {
    case MODE_SCMR:
        init_scmr(&ctx->task_ctx, ctx->args);
        break;

    case MODE_SCSR_SERIAL:
    case MODE_SCSR_CONCURRENT:
        init_scsr(&ctx->task_ctx, ctx->args);
        break;

    default:
        break;
    }
}


/* prevent from endless task */
static void kill_it_any_way_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t*)arg;
    event_base_loopbreak(ctx->eb);
    printf("[* tasks are running more than %d seconds, kill it anyway! *]\n", ctx->args->env_cfg.life);
}


void start_task_manager(client_ctx_t *ctx)
{
    init_tasks(ctx);

    /* init and arm task timer */
    ctx->ev_task = event_new(ctx->eb, -1, 0, task_schedule_callback, ctx);

    /* immediate engage task */
    task_schedule_callback(-1, 0, ctx);

    /* kill it anyway, to protect from endless task */
    if (ctx->args->env_cfg.life > 0) {
        struct timeval tv_kill_it_anyway = {ctx->args->env_cfg.life, 0};
        ctx->ev_kill = event_new(ctx->eb, -1, 0, kill_it_any_way_callback, ctx);
        event_add(ctx->ev_kill, &tv_kill_it_anyway);
    }
}


void free_ctx(client_ctx_t *ctx)
{
    client_close_keylog_file(ctx);
    client_close_log_file(ctx);

    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }

    free(ctx);
}



int main(int argc, char *argv[])
{
    /* get input client args */
    client_args_t *args = calloc(1, sizeof(client_args_t));
    init_client_args(args);
    parse_args(argc, argv, args);

    /* init client ctx */
    client_ctx_t *ctx = calloc(1, sizeof(client_ctx_t));;
    init_client_ctx(ctx, args);

    /* engine event */
    ctx->eb = event_base_new();
    ctx->ev_engine = event_new(ctx->eb, -1, 0, client_engine_callback, ctx);
    init_xquic_engine(ctx, args);

    /* start task scheduler */
    start_task_manager(ctx);

    event_base_dispatch(ctx->eb);

    xqc_engine_destroy(ctx->engine);
    free_ctx(ctx);
    return 0;
}
