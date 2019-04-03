#include <stdio.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include <event2/event.h>
#include <memory.h>

#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);

#define max_pkt_num 10
char send_buff[max_pkt_num][1500];
size_t send_buff_len[max_pkt_num];
int send_buff_idx = 0;

typedef struct client_ctx_s {
    int fd;
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    struct sockaddr *local_addr;
    socklen_t local_addrlen;
    struct sockaddr *peer_addr;
    socklen_t peer_addrlen;
    uint64_t send_offset;
    xqc_stream_t *stream;
} client_ctx_t;

int xqc_client_conn_notify(void *user_data, xqc_connection_t *conn) {
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    ctx->stream = xqc_create_stream(conn, user_data);
    return 0;
}

int xqc_client_write_notify(void *user_data, xqc_stream_t *stream) {
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[2000] = {0};
    xqc_stream_send(stream, buff, sizeof(buff), 1);

    return 0;
}

int xqc_client_read_notify(void *user_data, xqc_stream_t *stream) {
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    char buff[100] = {0};


    return 0;
}

ssize_t xqc_client_send(xqc_connection_t *c, unsigned char *buf, size_t size) {
    DEBUG;
    if (send_buff_idx >= max_pkt_num) {
        printf("exceed max_pkt_num\n");
        return -1;
    }
    memset(send_buff[send_buff_idx], 0, sizeof(send_buff[send_buff_idx]));
    memcpy(send_buff[send_buff_idx], buf, size);
    send_buff_len[send_buff_idx] = size;
    printf("=> send_buff_size %zu\n", send_buff_len[send_buff_idx]);
    send_buff_idx++;
    return size;
}


static void
recv_handler(int fd, short what, void *arg)
{
    DEBUG;
    client_ctx_t *ctx = (client_ctx_t *) arg;
    //printf("conn %x\n", ctx->conn);
    int idx = 0;
    for (; idx < send_buff_idx; idx++) {
        printf("=> recv size %d\n", send_buff_len[idx]);
        for (int i = 0; i < send_buff_len[idx]; i++) {
            printf("0x%02hhx ", send_buff[idx][i]);
        }
        printf("\n");

        if (xqc_engine_packet_process(ctx->engine, send_buff[idx], send_buff_len[idx],
                                      ctx->local_addr, ctx->local_addrlen,
                                      ctx->peer_addr, ctx->peer_addrlen, 0)) {
            printf("xqc_engine_packet_process error\n");
        }
    }

    //交还给xquic engine
    int rc = xqc_engine_main_logic(ctx->engine);
    if (rc) {
        printf("xqc_engine_main_logic error %d\n", rc);
        return ;
    }
}

static void
timer_handler(int fd, short what, void *arg) {
    DEBUG;
}

int main(int argc, char *argv[]) {
    printf("Usage: %s XQC_QUIC_VERSION:%d\n", argv[0], XQC_QUIC_VERSION);


    int rc;
    client_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    struct event_base *eb = event_base_new();

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT);

    xqc_engine_callback_t callback = {
            .conn_callbacks = {
                    .conn_create_notify = xqc_client_conn_notify,
            },
            .stream_callbacks = {
                    .stream_write_notify = xqc_client_write_notify,
                    .stream_read_notify = xqc_client_read_notify,
            },
            .write_socket = xqc_client_send,
    };
    xqc_engine_set_callback(ctx.engine, callback);


    ctx.conn = xqc_connect(ctx.engine, &ctx);
    if (!ctx.conn) {
        printf("xqc_connect error\n");
        return 0;
    }

    struct event *ev_tmo = event_new(eb, -1, 0, recv_handler, &ctx);
    struct timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;
    event_add(ev_tmo, &t);

    //struct event *ev_read = event_new(eb, sport->fd, EV_READ|EV_PERSIST, read_handler, sport);
    //event_add(ev_read, NULL);

    rc = xqc_engine_main_logic(ctx.engine);
    if (rc) {
        printf("xqc_engine_main_logic error %d\n", rc);
        return 0;
    }

    event_base_dispatch(eb);

    //xqc_client_write_notify(&ctx, ctx.stream);

    xqc_engine_destroy(ctx.engine);
    return 0;
}