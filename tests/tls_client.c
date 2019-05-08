#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include <event2/event.h>
#include <memory.h>
#include "xqc_tls_init.h"
#include "transport/crypto/xqc_tls_public.h"
#include "../include/xquic_typedef.h"
#include "transport/xqc_conn.h"

static char server_addr[256] = {0};
unsigned short server_port = 0;

unsigned long DCID_TEST = 0x1234567812345678;

int                 g_sock;
struct sockaddr_in  g_server_addr;


int do_handshake(xqc_connection_t * conn, xqc_cid_t * dcid){
    conn->tlsref.callbacks.client_initial(conn);


    xqc_list_head_t *head = &conn->tlsref.initial_pktns.msg_cb_head;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,head){
        xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
        if(buf->data_len > 0){
            char send_buf[1024*2];
            //NGTCP2_INITIAL_AEAD_OVERHEAD
            int ret =  sendto(g_sock, buf->data, buf->data_len, 0, (const void *)( &g_server_addr ), sizeof(g_server_addr));
            printf("client hello buf len:%d\n",buf->data_len );
            hex_print(buf->data, buf->data_len);

            buf->data_len  = 0;
            if(ret < 0){
                printf("error send data:%d",ret);
                return -1;
            }
        }
    }

    return 0;
}


int run(xqc_connection_t * conn, xqc_cid_t *dcid){
    do_handshake(conn, dcid);
    char buf[1024*2];
    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);
    while(1){
        int ret = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL );
        printf("recv server hello len:%d\n", ret);
        hex_print(buf,ret);
        conn->tlsref.callbacks.recv_crypto_data(conn, 0, buf, ret, NULL);
        if (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED){
            break;
        }
    }

    xqc_list_head_t *head = &conn->tlsref.hs_pktns.msg_cb_head;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,head){
        xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
        if(buf->data_len > 0){

            int ret =  sendto(g_sock, buf->data, buf->data_len, 0, (const void *)( &g_server_addr ), sizeof(g_server_addr));
            printf("client hs buf len:%d\n",buf->data_len );
            hex_print(buf->data, buf->data_len);

            buf->data_len  = 0;
            if(ret < 0){
                printf("error send data:%d",ret);
                return -1;
            }
        }
    }


    printf("Negotiated cipher suite is:%s\n",SSL_get_cipher_name(conn->xc_ssl));

    return 0;
}

int main(int argc, char *argv[]){

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);

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

    g_server_addr.sin_family = AF_INET;
    g_server_addr.sin_port = htons(server_port);
    (void)inet_aton((void *)server_addr, &g_server_addr.sin_addr);

    xqc_engine_t  engine;
    xqc_ssl_config_t xs_config;
    xqc_ssl_init_config(&xs_config, NULL, NULL);

    int no_crypto_flag = 1; // 1 means no crypto

    engine.ssl_ctx = xqc_create_client_ssl_ctx(&xs_config);
    xqc_connection_t conn;
    xqc_tlsref_init(& conn.tlsref);
    xqc_cid_t dcid;
    memcpy(dcid.cid_buf, &DCID_TEST, sizeof(DCID_TEST));
    dcid.cid_len = sizeof(DCID_TEST);
    //xqc_create_client_ssl(&engine, &conn,  server_addr,
    xqc_client_tls_initial(&engine, &conn, server_addr, &xs_config, &dcid, no_crypto_flag);

    xqc_client_setup_initial_crypto_context(&conn, &dcid);
    conn.version = XQC_QUIC_VERSION;
    run(&conn, &dcid);


}
