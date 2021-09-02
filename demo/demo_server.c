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
#include <ctype.h>

#include "common.h"



#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)


/**
 * ============================================================================
 * the network config definition section
 * network config is those arguments about socket connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8443

typedef struct net_config_s
{
    /* server addr info */
    struct sockaddr addr;
    int     addr_len;
    char    ip[64];
    short   port;

    /* ipv4 or ipv6 */
    int     ipv6;

    /* congestion control algorithm */
    CC_TYPE cc;     /* congestion control algorithm */
    int     pacing; /* is pacing on */

    /* idle persist timeout */
    int     conn_timeout;
} net_config_t;



/**
 * ============================================================================
 * the quic config definition section
 * quic config is those arguments about quic connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

#define SESSION_TICKET_KEY_FILE     "session_ticket.key"
#define SESSION_TICKET_KEY_BUF_LEN  2048
typedef struct quic_config_s
{
    /* cipher config */
    char cipher_suit[CIPHER_SUIT_LEN];
    char groups[TLS_GROUPS_LEN];

    /* 0-rtt config */
    int  stk_len;                           /* session ticket len */
    char stk[SESSION_TICKET_KEY_BUF_LEN];   /* session ticket buf */

    /* retry */
    int  retry_on;
} quic_config_t;


/**
 * ============================================================================
 * the environment config definition section
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 * ============================================================================
 */

#define LOG_PATH "slog.log"
#define KEY_PATH "skeys.log"
#define SOURCE_DIR  "."
#define PRIV_KEY_PATH "server.key"
#define CERT_PEM_PATH "server.crt"



/* environment config */
typedef struct env_config_s
{
    /* log path */
    char    log_path[PATH_LEN];
    int     log_level;

    /* source file dir */
    char    source_file_dir[RESOURCE_LEN];

    /* tls certs */
    char    priv_key_path[PATH_LEN];
    char    cert_pem_path[PATH_LEN];

    /* key export */
    int     key_output_flag;
    char    key_out_path[PATH_LEN];
} env_config_t;


typedef struct server_args_s {
    /* network args */
    net_config_t    net_cfg;

    /* quic args */
    quic_config_t   quic_cfg;

    /* environment args */
    env_config_t    env_cfg;
} server_args_t;



typedef struct server_ctx_s {
    xqc_engine_t        *engine;
    struct event        *ev_engine;

    /* ipv4 server */
    int                 fd;
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct event        *ev_socket;

    /* ipv6 server */
    int                 fd6;
    struct sockaddr_in6 local_addr6;
    socklen_t           local_addrlen6;
    struct event        *ev_socket6;

    /* fd or fd6, used to remember fd type to send stateless reset */
    int                 current_fd;

    int                 log_fd;
    int                 keylog_fd;

    server_args_t       *args;
} server_ctx_t;


typedef struct user_conn_s {
    struct event       *ev_timeout;
    struct sockaddr_in6 peer_addr;
    socklen_t           peer_addrlen;
    xqc_cid_t           cid;
    server_ctx_t        *ctx;
} user_conn_t;

typedef struct resource_s
{
    FILE    *fp;
    int     total_len;      /* total len of file */
    int     total_offset;   /* total sent offset of file */
    char    *buf;           /* send buf */
    int     buf_size;       /* send buf size */
    int     buf_len;        /* send buf len */
    int     buf_offset;     /* send buf offset */
} resource_t;


#define REQ_BUF_SIZE    2048
#define REQ_H3_BODY_SIZE 1024 * 1024
typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;

    // uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    size_t              send_body_len;
    size_t              recv_body_len;
    char               *recv_buf;

    user_conn_t         *conn;
    resource_t          res;  /* resource info */
} user_stream_t;


/* the global unique server context */
server_ctx_t svr_ctx;


static inline uint64_t now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}

void xqc_server_set_event_timer(xqc_msec_t wake_after, void *user_data)
{
    server_ctx_t *ctx = (server_ctx_t *)user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

int read_file_data(char * data, size_t data_len, char *filename)
{
    FILE * fp = fopen(filename, "rb");
    if (fp == NULL) {
        return -1;
    }

    fseek(fp, 0 , SEEK_END);
    size_t total_len  = ftell(fp);
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

int xqc_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data)
{
    DEBUG;
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    xqc_conn_set_user_data(conn, user_conn);
    printf("xqc_server_conn_create_notify, user_conn: %p, conn: %p\n", user_conn, conn);

    /* set ctx */
    user_conn->ctx = (server_ctx_t*)conn_user_data; // TODO:

    /* set addr info */
    socklen_t peer_addrlen;
    struct sockaddr* peer_addr = xqc_conn_get_peer_addr(conn, &peer_addrlen);
    memcpy(&user_conn->peer_addr, peer_addr, peer_addrlen);
    user_conn->peer_addrlen = peer_addrlen;

    return 0;
}

int xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t*)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" "
        "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count, stats.lost_count,
        stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    user_conn = NULL;
    return 0;
}

void xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *conn_user_data)
{
    DEBUG;
    printf("xqc_server_conn_handshake_finished, user_data: %p, conn: %p\n", conn_user_data, conn);
    user_conn_t *user_conn = (user_conn_t *)conn_user_data;
}


/* 密钥回调 */
void
xqc_server_tls_key_cb(char *key, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (user_conn->ctx->args->env_cfg.key_output_flag
        && strlen(user_conn->ctx->args->env_cfg.key_out_path))
    {
        FILE* pkey = fopen(user_conn->ctx->args->env_cfg.key_out_path, "a+");
        if (NULL == pkey) {
            return;
        }

        fprintf(pkey, key);
        fclose(pkey);
    }
}

int server_stream_send(user_stream_t *user_stream, char* data, ssize_t len, int fin)
{
    ssize_t ret = xqc_stream_send(user_stream->stream, data, len, fin);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
    }

    return ret;
}

int xqc_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
    user_stream->stream = stream;
    user_stream->conn = (user_conn_t*)user_data;
    xqc_stream_set_user_data(stream, user_stream);

    user_stream->recv_buf = calloc(1, REQ_BUF_SIZE);

    return 0;
}

int xqc_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream);
    return 0;
}

void close_user_stream_resource(user_stream_t * user_stream)
{
    if (user_stream->res.buf) {
        free(user_stream->res.buf);
        user_stream->res.buf = NULL;
    }

    if (user_stream->res.fp)
    {
        fclose(user_stream->res.fp);
        user_stream->res.fp = NULL;
    }
}

/**
 * send buf utill EAGAIN
 * [return] > 0: finish send; 0: not finished
 */
int send_file(xqc_stream_t *stream, user_stream_t *user_stream)
{
    int ret = 0;
    resource_t *res = &user_stream->res;
    while (res->total_offset < res->total_len) {   /* still have bytes to be sent */
        char *send_buf = NULL;  /* the buf need to be send */
        int send_len = 0;       /* len of the the buf gonna be sent */
        if (res->buf_offset < res->buf_len) {
            /* prev buf not sent completely, continue send from last offset */
            send_buf = res->buf + res->buf_offset;
            send_len = res->buf_len - res->buf_offset;

        } else {
            /* prev buf sent, read new buf and send */
            res->buf_offset = 0;
            res->buf_len = fread(res->buf, 1, res->buf_size, res->fp);
            if (res->buf_len <= 0) {
                return -1;
            }
            send_buf = res->buf;
            send_len = res->buf_len;
        }

        /* send buf */
        int fin = send_len + res->total_offset == res->total_len ? 1 : 0;
        ret = server_stream_send(user_stream, send_buf, send_len, fin);

/*        printf("total_len: %d, total_offset: %d, buf_len: %d, buf_offset: %d, send_len: %d, fin: %d, ret: %d\n",
                res->total_len, res->total_offset, res->buf_len, res->buf_offset, send_len, fin, ret);
*/
        if (ret > 0) {
            res->buf_offset += ret;
            res->total_offset += ret;

        } else if (ret == 0) {
            break;

        } else {
            printf("send file data failed!!: ret: %d\n", ret);
            return -1;
        }
    }

    return res->total_offset == res->total_len;
}

int xqc_server_stream_write_notify(xqc_stream_t *stream, void *strm_user_data)
{
    DEBUG;
    //printf("xqc_server_stream_write_notify user_data: %p\n", user_data);
    user_stream_t *user_stream = (user_stream_t*)strm_user_data;
    int ret = send_file(stream, user_stream);
    if (ret != 0) {
        /* error or finish, close stream */
        close_user_stream_resource(user_stream);
    }

    return 0;
}

int xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    char buff[4096] = {0};
    size_t buff_size = 4096;
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
        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    return 0;
}


void handle_hq_request(user_stream_t *user_stream, xqc_stream_t *stream, char *req, ssize_t len)
{
    /* parse request */
    char method[16] = {0};
    char resource[RESOURCE_LEN] = {0};
    int ret = sscanf(req, "%s %s", method, resource);
    if (ret <= 0) {
        printf("parse hq request failed: %s\n", req);
        return;
    }

    /* format file path */
    char file_path[PATH_LEN] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", user_stream->conn->ctx->args->env_cfg.source_file_dir, resource);
    user_stream->res.fp = fopen(file_path, "rb");
    if (NULL == user_stream->res.fp) {
        printf("error open file [%s]\n", file_path);
        goto handle_error;
    }
    printf("open file[%s] suc, user_conn: %p\n", file_path, user_stream->conn);

    /* create buf */
    user_stream->res.buf = (char*)malloc(READ_FILE_BUF_LEN);
    if (NULL == user_stream->res.buf) {
        printf("error create stream buf\n");
        goto handle_error;
    }
    user_stream->res.buf_size = READ_FILE_BUF_LEN;

    /* get total len */
    fseek(user_stream->res.fp, 0 , SEEK_END);
    user_stream->res.total_len = ftell(user_stream->res.fp);
    fseek(user_stream->res.fp, 0, SEEK_SET);

    /* begin to send file */
    ret = send_file(stream, user_stream);
    if (ret == 0) {
        return;
    }

handle_error:
    close_user_stream_resource(user_stream);
}

int xqc_server_hq_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *)user_data;
    ssize_t read;
    do {
        char *buf = user_stream->recv_buf + user_stream->recv_body_len;
        size_t buf_size = REQ_BUF_SIZE - user_stream->recv_body_len;
        read = xqc_stream_recv(stream, buf, buf_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (fin) {
        handle_hq_request(user_stream, stream, user_stream->recv_buf, user_stream->recv_body_len);
    }
    return 0;
}




/******************************************************************************
 *                     start of http/3 callback functions                     *
 ******************************************************************************/

int
server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    server_ctx_t *ctx = (server_ctx_t*)user_data;

    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    user_conn->ctx = ctx;
    xqc_h3_conn_set_user_data(h3_conn, user_conn);
    printf("server_h3_conn_create_notify, user_conn: %p, h3_conn: %p\n", user_conn, h3_conn);

    socklen_t peer_addrlen;
    struct sockaddr* peer_addr = xqc_h3_conn_get_peer_addr(h3_conn, &peer_addrlen);
    memcpy(&user_conn->peer_addr, peer_addr, peer_addrlen);
    user_conn->peer_addrlen = peer_addrlen;

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    return 0;
}

int
server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" "
            "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count,
            stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt,
            stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    user_conn = NULL;
    return 0;
}

void 
server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);
}


int server_h3_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;
    user_stream->conn = (user_conn_t*)strm_user_data;

    xqc_h3_request_set_user_data(h3_request, user_stream);
    user_stream->recv_buf = calloc(1, REQ_BUF_SIZE);

    return 0;
}

int server_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)strm_user_data;
    close_user_stream_resource(user_stream);
    free(user_stream);

    return 0;
}


void
server_set_rsp_header_value_str(xqc_http_headers_t *rsp_hdrs, H3_HDR_TYPE hdr_type, char *v)
{
    rsp_hdrs->headers[hdr_type].value.iov_base = v;
    rsp_hdrs->headers[hdr_type].value.iov_len = strlen(v);
}

void
server_set_rsp_header_value_int(xqc_http_headers_t *rsp_hdrs, H3_HDR_TYPE hdr_type, int v)
{
    sprintf(rsp_hdrs->headers[hdr_type].value.iov_base, "%d", v);
    rsp_hdrs->headers[hdr_type].value.iov_len = strlen(
        (char*)rsp_hdrs->headers[hdr_type].value.iov_base);
}


int server_request_send_body(user_stream_t *user_stream, char* data, ssize_t len, int fin)
{
    ssize_t ret = xqc_h3_request_send_body(user_stream->h3_request, data, len, fin);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
    }

    return ret;
}

int
server_send_body(user_stream_t *user_stream)
{
    int ret = 0;
    resource_t *res = &user_stream->res;
    while (res->total_offset < res->total_len) {   /* still have bytes to be sent */
        char *send_buf = NULL;  /* the buf need to be send */
        int send_len = 0;       /* len of the the buf gonna be sent */
        if (res->buf_offset < res->buf_len) {
            /* prev buf not sent completely, continue send from last offset */
            send_buf = res->buf + res->buf_offset;
            send_len = res->buf_len - res->buf_offset;

        } else {
            /* prev buf sent, read new buf and send */
            res->buf_offset = 0;
            res->buf_len = fread(res->buf, 1, res->buf_size, res->fp);
            if (res->buf_len <= 0) {
                return -1;
            }
            send_buf = res->buf;
            send_len = res->buf_len;
        }

        /* send buf */
        int fin = send_len + res->total_offset == res->total_len ? 1 : 0;
        ret = server_request_send_body(user_stream, send_buf, send_len, fin);

/*        printf("total_len: %d, total_offset: %d, buf_len: %d, buf_offset: %d, send_len: %d, fin: %d, ret: %d\n",
                res->total_len, res->total_offset, res->buf_len, res->buf_offset, send_len, fin, ret);
*/
        if (ret > 0) {
            res->buf_offset += ret;
            res->total_offset += ret;

        } else if (ret == 0) {
            break;

        } else {
            printf("send file data failed!!: ret: %d\n", ret);
            return -1;
        }
    }

    return res->total_offset == res->total_len;
}

int
server_handle_h3_request(user_stream_t *user_stream, xqc_http_headers_t *req_hdrs)
{
    DEBUG;
    ssize_t ret = 0;

    /* response header buf list */
    char rsp_hdr_buf[H3_HDR_CNT][RSP_HDR_BUF_LEN];
    xqc_http_header_t rsp_hdr[] = {
        {
            .name = {.iov_base = ":status", .iov_len = 7},
            .value = {.iov_base = rsp_hdr_buf[H3_HDR_STATUS], .iov_len = 0},
            .flags = 0,
        },
        {
            .name = {.iov_base = "content-type", .iov_len = 12},
            .value = {.iov_base = "text/plain", .iov_len = 10},
            .flags = 0,
        },
        {
            .name = {.iov_base = "content-length", .iov_len = 14},
            .value = {.iov_base = rsp_hdr_buf[H3_HDR_CONTENT_LENGTH], .iov_len = 0},
            .flags = 0,
        }
    };
    /* response header */
    xqc_http_headers_t rsp_hdrs;
    rsp_hdrs.headers = rsp_hdr;
    rsp_hdrs.count = sizeof(rsp_hdr) / sizeof(rsp_hdr[0]);

    /* format file path */
    char file_path[PATH_LEN] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", 
        user_stream->conn->ctx->args->env_cfg.source_file_dir, user_stream->recv_buf);
    user_stream->res.fp = fopen(file_path, "rb");
    if (NULL == user_stream->res.fp) {
        printf("error open file [%s]\n", file_path);
        server_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 404);
        goto h3_handle_error;
    }

    /* create buf */
    user_stream->res.buf = (char*)malloc(READ_FILE_BUF_LEN);
    if (NULL == user_stream->res.buf) {
        printf("error create stream buf\n");
        server_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 500);
        goto h3_handle_error;
    }
    user_stream->res.buf_size = READ_FILE_BUF_LEN;

    /* get total len */
    fseek(user_stream->res.fp, 0 , SEEK_END);
    user_stream->res.total_len = ftell(user_stream->res.fp);
    fseek(user_stream->res.fp, 0, SEEK_SET);

    server_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_CONTENT_LENGTH, user_stream->res.total_len);
    server_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 200);

    /* send header first */
    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &rsp_hdrs, 0);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }
    }

    /* begin to send file */
    ret = server_send_body(user_stream);
    if (ret == 0) {
        return 0;
    }

h3_handle_error:
    close_user_stream_resource(user_stream);
    return -1;
}


int server_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    DEBUG;
    int ret;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *)strm_user_data;

    /* recv headers */
    xqc_http_headers_t *headers;
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        /* print headers */
        for (int i = 0; i < headers->count; i++) {
            /* save path */
            if (strcmp((char*)headers->headers[i].name.iov_base, ":path") == 0) {
                strncpy(user_stream->recv_buf, (char*)headers->headers[i].value.iov_base, headers->headers[i].value.iov_len);
            }
            printf("%s = %s\n",(char*)headers->headers[i].name.iov_base,
                (char*)headers->headers[i].value.iov_base);
        }

        printf("fin: %d\n", fin);

        /* TODO: if recv headers once for all? */
        user_stream->header_recvd = 1;

    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {   /* recv body */
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

            read_sum += read;
            user_stream->recv_body_len += read;
        } while (read > 0 && !fin);

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }

    if (fin) {
        server_handle_h3_request(user_stream, headers);
    }

    return 0;
}


int server_h3_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    //printf("server_h3_request_write_notify user_data: %p\n", user_data);
    user_stream_t *user_stream = (user_stream_t*)user_data;
    int ret = server_send_body(user_stream);

#if 0
    if (ret != 0) {
        /* error or finish, close stream */
        close_user_stream_resource(user_stream);
    }
#endif

    return ret;
}


/******************************************************************************
 *                     start of socket operation function                     *
 ******************************************************************************/

ssize_t
xqc_server_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    ssize_t res;
    /* conn_user_data might be NULL when server sending stateless reset token */
    int fd = svr_ctx.current_fd;

    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_server_write_socket err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));

    return res;
}


void
xqc_server_socket_write_handler(server_ctx_t *ctx, int fd)
{
    DEBUG
}

void
xqc_server_socket_read_handler(server_ctx_t *ctx, int fd)
{
    DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    ctx->current_fd = fd;

    do {
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *) &peer_addr, &peer_addrlen);
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
        int ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *)(&peer_addr), peer_addrlen,
                                      (xqc_usec_t)recv_time, ctx);
        if (ret != 0) {
            printf("xqc_server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
    ctx->current_fd = -1;
}


static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    server_ctx_t *ctx = (server_ctx_t *)arg;
    if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx, fd);

    } else if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}

int xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data)
{
    DEBUG;

    return 0;
}

/* create socket and bind port */
static int init_socket(int family, uint16_t port, 
        struct sockaddr *local_addr, socklen_t local_addrlen)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    /* non-block */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    /* reuse port */
    int opt_reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_reuseaddr, sizeof(opt_reuseaddr)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    /* send/recv buffer size */
    int size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    /* bind port */
    if (bind(fd, local_addr, local_addrlen) < 0) {
        printf("bind socket failed, family: %d, errno: %d, %s\n", family, errno, strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int xqc_server_create_socket(server_ctx_t *ctx, net_config_t* cfg)
{
    /* ipv4 socket */
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    ctx->local_addr.sin_family = AF_INET;
    ctx->local_addr.sin_port = htons(cfg->port);
    ctx->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addrlen = sizeof(ctx->local_addr);
    ctx->fd = init_socket(AF_INET, cfg->port, (struct sockaddr*)&ctx->local_addr, ctx->local_addrlen);

    /* ipv6 socket */
    memset(&ctx->local_addr6, 0, sizeof(ctx->local_addr6));
    ctx->local_addr6.sin6_family = AF_INET6;
    ctx->local_addr6.sin6_port = htons(cfg->port);
    ctx->local_addr6.sin6_addr = in6addr_any;
    ctx->local_addrlen6 = sizeof(ctx->local_addr6);
    ctx->fd6 = init_socket(AF_INET6, cfg->port, (struct sockaddr*)&ctx->local_addr6, ctx->local_addrlen6);


    if (!ctx->fd && !ctx->fd6) {
        return -1;
    }

    return 0;
}


static void
xqc_server_engine_callback(int fd, short what, void *arg)
{
    server_ctx_t *ctx = (server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}


/******************************************************************************
 *                       start of server keylog functions                     *
 ******************************************************************************/
int server_open_log_file(server_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int server_close_log_file(server_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

void server_write_log_file(const void *buf, size_t size, void *engine_user_data)
{
    server_ctx_t *ctx = (server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }

    write(ctx->log_fd, buf, size);
}


/******************************************************************************
 *                       start of server keylog functions                     *
 ******************************************************************************/
int server_open_keylog_file(server_ctx_t *ctx)
{
    ctx->keylog_fd = open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;    
}

int server_close_keylog_file(server_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }
    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}

void xqc_keylog_cb(const char *line, void *user_data)
{
    server_ctx_t *ctx = (server_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    write(ctx->keylog_fd, line, strlen(line));
    write(ctx->keylog_fd, "\n", 1);
}


void usage(int argc, char *argv[])
{
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
            "Usage: %s [Options]\n"
            "\n"
            "Options:\n"
            "   -p    Server port.\n"
            "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic\n"
            "   -C    Pacing on.\n"
            "   -l    Log level. e:error d:debug.\n"
            "   -L    xuqic log directory.\n"
            "   -6    IPv6\n"
            "   -k    Key output file path\n"
            "   -r    retry\n"
            , prog);
}

void init_0rtt(server_args_t *args)
{
    /* read session ticket key */
    int ret = read_file_data(args->quic_cfg.stk,
            SESSION_TICKET_KEY_BUF_LEN, SESSION_TICKET_KEY_FILE);
    args->quic_cfg.stk_len = ret > 0 ? ret : 0;
}


void init_server_args(server_args_t *args)
{
    memset(args, 0, sizeof(server_args_t));

    /* net cfg */
    strcpy(args->net_cfg.ip, DEFAULT_IP);
    args->net_cfg.port = DEFAULT_PORT;

    /* quic cfg */
    init_0rtt(args);
    strcpy(args->quic_cfg.cipher_suit, XQC_TLS_CIPHERS);
    strcpy(args->quic_cfg.groups, XQC_TLS_GROUPS);

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strcpy(args->env_cfg.log_path, LOG_PATH);
    strcpy(args->env_cfg.source_file_dir, SOURCE_DIR);
    strcpy(args->env_cfg.priv_key_path, PRIV_KEY_PATH);
    strcpy(args->env_cfg.cert_pem_path, CERT_PEM_PATH);

}

void parse_args(int argc, char *argv[], server_args_t *args)
{
    int ch = 0;
    while((ch = getopt(argc, argv, "p:c:CD:l:L:6k:r")) != -1){
        switch(ch)
        {
        /* listen port */
        case 'p':
            printf("option port :%s\n", optarg);
            args->net_cfg.port = atoi(optarg);
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

        /* server resource dir */
        case 'D':
            printf("option read dir :%s\n", optarg);
            strncpy(args->env_cfg.source_file_dir, optarg, RESOURCE_LEN);
            break;

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            args->env_cfg.log_level = optarg[0];
            break;

        /* log path */
        case 'L': // log directory
            printf("option log directory :%s\n", optarg);
            snprintf(args->env_cfg.log_path, sizeof(args->env_cfg.log_path), "%s", optarg);
            break;

        /* ipv6 */
        case '6': //IPv6
            printf("option IPv6 :%s\n", "on");
            args->net_cfg.ipv6 = 1;
            break;

        /* key out path */
        case 'k': // key out path
            printf("option key output file: %s\n", optarg);
            args->env_cfg.key_output_flag = 1;
            strncpy(args->env_cfg.key_out_path, optarg, sizeof(args->env_cfg.key_out_path));
            break;

        /* retry */
        case 'r':
            printf("option validate addr with retry packet\n");
            args->quic_cfg.retry_on = 1;
            break;

        default:
            printf("other option :%c\n", ch);
            usage(argc, argv);
            exit(0);
        }
    }
}

void init_callback(xqc_engine_callback_t *cb, server_args_t* args)
{
    static xqc_engine_callback_t callback = {
        .conn_callbacks = {
            .conn_create_notify = xqc_server_conn_create_notify,
            .conn_close_notify = xqc_server_conn_close_notify,
            .conn_handshake_finished = xqc_server_conn_handshake_finished,
        },
        .h3_conn_callbacks = {
            .h3_conn_create_notify = server_h3_conn_create_notify,
            .h3_conn_close_notify = server_h3_conn_close_notify,
            .h3_conn_handshake_finished = server_h3_conn_handshake_finished,
        },
        .stream_callbacks = {
            .stream_write_notify = xqc_server_stream_write_notify,
            .stream_read_notify = xqc_server_stream_read_notify,
            .stream_create_notify = xqc_server_stream_create_notify,
            .stream_close_notify = xqc_server_stream_close_notify,
        },
        .hq_stream_callbacks = {
            .stream_write_notify = xqc_server_stream_write_notify,
            .stream_read_notify = xqc_server_hq_stream_read_notify,
            .stream_create_notify = xqc_server_stream_create_notify,
            .stream_close_notify = xqc_server_stream_close_notify,
        },
        .h3_request_callbacks = {
            .h3_request_write_notify = server_h3_request_write_notify,
            .h3_request_read_notify = server_h3_request_read_notify,
            .h3_request_create_notify = server_h3_request_create_notify,
            .h3_request_close_notify = server_h3_request_close_notify,
        },
        .write_socket = xqc_server_write_socket,
        .server_accept = xqc_server_accept,
        .set_event_timer = xqc_server_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = server_write_log_file,
            .xqc_log_write_stat = server_write_log_file
        },
        .keylog_cb = xqc_keylog_cb,
    };

    *cb = callback;
}

/* init server ctx */
void init_server_ctx(server_ctx_t *ctx, server_args_t *args)
{
    memset(ctx, 0, sizeof(server_ctx_t));
    ctx->current_fd = -1;
    ctx->args = args;
    server_open_log_file(ctx);
    server_open_keylog_file(ctx);
}

/* init ssl config */
void init_ssl_config(xqc_engine_ssl_config_t *cfg, server_args_t *args)
{
    cfg->private_key_file = args->env_cfg.priv_key_path;
    cfg->cert_file = args->env_cfg.cert_pem_path;
    cfg->ciphers = args->quic_cfg.cipher_suit;
    cfg->groups = args->quic_cfg.groups;
    cfg->alpn_list = NULL;
    cfg->alpn_list_len = 0;

    if (args->quic_cfg.stk_len <= 0) {
        cfg->session_ticket_key_data = NULL;
        cfg->session_ticket_key_len = 0;

    } else {
        cfg->session_ticket_key_data = args->quic_cfg.stk;
        cfg->session_ticket_key_len = args->quic_cfg.stk_len;
    }
}

void init_conn_settings(server_args_t *args)
{
    xqc_cong_ctrl_callback_t ccc = {0};
    switch (args->net_cfg.cc)
    {
    case CC_TYPE_BBR:
        ccc = xqc_bbr_cb;
        break;
    case CC_TYPE_CUBIC:
        ccc = xqc_cubic_cb;
        break;
    case CC_TYPE_RENO:
        ccc = xqc_reno_cb;
        break;
    default:
        break;
    }

    /* init connection settings */
    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   args->net_cfg.pacing,
        .cong_ctrl_callback = ccc,
        .cc_params = {
            .customize_on = 1,
            .init_cwnd = 32,
        },
        .spurious_loss_detect_on = 1,
    };

    xqc_server_set_conn_settings(&conn_settings);
}

/* init xquic server engine */
int init_xquic_engine(server_ctx_t *ctx, server_args_t *args)
{
    /* init engine ssl config */
    xqc_engine_ssl_config_t cfg = {0};
    init_ssl_config(&cfg, args);

    /* init engine callbacks */
    xqc_engine_callback_t callback;
    init_callback(&callback, args);

    /* init server connection settings */
    init_conn_settings(args);

    /* init engine config */
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

    /* create server engine */
    ctx->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &cfg, &callback, ctx);
    if (ctx->engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    return 0;
}

#if 0
void stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
}
#endif


void free_ctx(server_ctx_t *ctx)
{
    server_close_keylog_file(ctx);
    server_close_log_file(ctx);

    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }

    free(ctx);
}


int main(int argc, char *argv[])
{
    /* get input server args */
    server_args_t *args = calloc(1, sizeof(server_args_t));
    init_server_args(args);
    parse_args(argc, argv, args);

    /* init server ctx */
    server_ctx_t *ctx = &svr_ctx;
    init_server_ctx(ctx, args);

    /* engine event */
    struct event_base *eb = event_base_new();
    ctx->ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, ctx);

    if (init_xquic_engine(ctx, args) < 0) {
        return -1;
    }

    /* init socket */
    int ret = xqc_server_create_socket(ctx, &args->net_cfg);
    if (ret < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    /* socket event */
    ctx->ev_socket = event_new(eb, ctx->fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, ctx);
    event_add(ctx->ev_socket, NULL);

    /* socket event */
    ctx->ev_socket6 = event_new(eb, ctx->fd6, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, ctx);
    event_add(ctx->ev_socket6, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx->engine);
    free_ctx(ctx);

    return 0;
}
