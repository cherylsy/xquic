#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include "xqc_cmake_config.h"
#include "include/xquic.h"
#include <event2/event.h>
#include <memory.h>
#include "transport/crypto/xqc_tls_public.h"
#include "include/xquic_typedef.h"
#include "transport/xqc_conn.h"
#include "transport/crypto/xqc_tls_init.h"

//static char server_addr[256] = {0};
unsigned short g_listen_port = 0;
char g_key_file[256] = {0};
char g_cert_file[256] = {0};

int                 g_sock;
struct sockaddr_in  g_addr;



unsigned long DCID_TEST = 0x1234567812345678;

int run(xqc_connection_t *conn){
    char buf[2048];
    xqc_cid_t dcid;
    memcpy(dcid.cid_buf, &DCID_TEST, sizeof(DCID_TEST));
    dcid.cid_len = sizeof(DCID_TEST);

    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);

    while(1){
        int n = recvfrom(g_sock, buf, sizeof(buf), 0, (struct sockaddr *)(&g_client_addr), &len );

        if(n > 0){
            hex_print(buf, n);
            //recv_client_initial(conn, &dcid, NULL);
            //xqc_recv_client_hello_derive_key(conn, &dcid);
            conn->tlsref.callbacks.recv_client_initial(conn, &dcid, NULL);//recv client initial packets
            conn->tlsref.callbacks.recv_crypto_data(conn, 0, buf, n, NULL);
        }

        xqc_list_head_t *head = &conn->tlsref.initial_pktns.msg_cb_head;
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(pos, next, head){
            xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
            if(buf->data_len > 0){
                printf("in initial pktns:%d\n",buf->data_len);
                int ret =  sendto(g_sock, buf->data, buf->data_len, 0, (struct sockaddr *)(&g_client_addr), len);
                buf->data_len = 0;
                if(ret < 0){
                    printf("error send\n");
                    return -1;
                }
            }
            xqc_list_del(pos);
            free(pos);
        }

        head = &conn->tlsref.hs_pktns.msg_cb_head;
        xqc_list_for_each_safe(pos, next, head){
            xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
            if(buf->data_len > 0){
                printf("in hs pktns:%d\n", buf->data_len);
                int ret =  sendto(g_sock, buf->data, buf->data_len, 0, (struct sockaddr *)&g_client_addr, len);
                buf->data_len = 0;
                if(ret < 0){
                    printf("error send\n");
                    return -1;
                }
            }
            xqc_list_del(pos);
            free(pos);
        }


        if(conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
            break;
        }
    }
    printf("Negotiated cipher suite is:%s\n",SSL_get_cipher_name(conn->xc_ssl));

}


int main(int argc, char *argv[]){
    int ch = 0;
    while((ch = getopt(argc, argv, "l:k:c:")) != -1){
        switch(ch)
        {
            case 'l':
                printf("option l:'%s'\n", optarg);
                g_listen_port = atoi(optarg);
                break;
            case 'k':
                printf("option keyfile :%s\n", optarg);
                snprintf(g_key_file, sizeof(g_key_file), optarg);
                break;
            case 'c':
                printf("opetion cert file:%s\n",optarg);
                snprintf(g_cert_file, sizeof(g_key_file), optarg);
                break;
            default:
                printf("other option :%c\n", ch);
                exit(0);
        }

    }


    g_addr.sin_family = AF_INET;
    g_addr.sin_port = htons(g_listen_port);
    g_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ( (g_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }


    if (bind(g_sock, (struct sockaddr *)&g_addr, sizeof(g_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    xqc_engine_t  engine;
    xqc_ssl_config_t xs_config;
    xqc_ssl_init_config(&xs_config, g_key_file, g_cert_file, NULL);

    engine.ssl_ctx = xqc_create_server_ssl_ctx(&xs_config);
    xqc_connection_t conn;
    conn.version = XQC_QUIC_VERSION;
    xqc_tlsref_init(& conn.tlsref);
    xqc_server_tls_initial(&engine, &conn, &xs_config);
    conn.tlsref.server = 1;

    run(&conn);

}
