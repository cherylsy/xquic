#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include "xqc_cmake_config.h"
#include "../include/xquic.h"
#include <event2/event.h>
#include <memory.h>
#include "transport/crypto/xqc_tls_public.h"
#include "../include/xquic_typedef.h"
#include "transport/xqc_conn.h"
#include "transport/crypto/xqc_tls_init.h"

#define TEST_PKT_HEADER_LEN 16
//static char server_addr[256] = {0};
unsigned short g_listen_port = 0;
char g_key_file[256] = {0};
char g_cert_file[256] = {0};

int                 g_sock;
struct sockaddr_in  g_addr;

int init_pkt_header(unsigned char * dest, int n){
    int i = 0;
    for(i = 0; i < n ; i++){
        dest[i] = 0xff;
    }
    return 0;
}




unsigned long DCID_TEST = 0x1234567812345678;

int send_server_handshake(xqc_connection_t * conn, xqc_pktns_t * p_pktns , xqc_encrypt_t encrypt_func , struct sockaddr_in * p_client_addr ){

    //xqc_list_head_t *head = &conn->tlsref.initial_pktns.msg_cb_head;
    xqc_list_head_t *head = &(p_pktns -> msg_cb_head);
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head){
        xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
        if(buf->data_len > 0){
            unsigned char send_buf[1024*2];
            unsigned char * pkt_header = send_buf;
            unsigned char * pkt_data = pkt_header + TEST_PKT_HEADER_LEN ;
            init_pkt_header(pkt_header,  TEST_PKT_HEADER_LEN);

            //uint64_t pkt_num = 0;
            uint8_t nonce[32];
            xqc_crypto_km_t *p_ckm = & p_pktns->tx_ckm;
            xqc_vec_t  * p_hp = & p_pktns->tx_hp;
            memcpy(pkt_data, buf->data, buf->data_len);
            xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);


            printf("encrypt key:\n");
            hex_print(p_ckm->key.base, p_ckm->key.len);
            printf("nonce:\n");
            hex_print(nonce, p_ckm->iv.len);
            printf("aead:\n");
            hex_print(pkt_header, TEST_PKT_HEADER_LEN);


            size_t nwrite = encrypt_func(conn, pkt_data, sizeof(send_buf) - TEST_PKT_HEADER_LEN, pkt_data, buf->data_len, p_ckm->key.base, p_ckm->key.len, nonce,p_ckm->iv.len, pkt_header, TEST_PKT_HEADER_LEN, NULL);

            if(nwrite <= 0){
                printf("error encrypt\n");
                return -1;
            }
            printf("encrypt %d bytes\n", nwrite);
            hex_print(send_buf, nwrite + TEST_PKT_HEADER_LEN);

            int ret =  sendto(g_sock, send_buf, nwrite + TEST_PKT_HEADER_LEN, 0, (struct sockaddr *)(p_client_addr), sizeof(struct sockaddr_in));
            buf->data_len = 0;
            if(ret < 0){
                printf("error send\n");
                return -1;
            }
        }
        xqc_list_del(pos);
        free(pos);
    }
    return 0;

}



int recv_client_hello( xqc_connection_t *conn, struct sockaddr_in * p_client_addr, char * recv_buf, size_t buf_len ){
    xqc_cid_t dcid;
    memcpy(dcid.cid_buf, &DCID_TEST, sizeof(DCID_TEST));
    dcid.cid_len = sizeof(DCID_TEST);
    conn->tlsref.callbacks.recv_client_initial(conn, &dcid, NULL);//recv client initial packets

    char buf[2*1024];
    int len = sizeof(struct sockaddr_in);

    while(1){
        int recv_len = recvfrom(g_sock, buf, sizeof(buf), 0, (struct sockaddr *) p_client_addr, &len );
        if(recv_len < 0){
            return -1;
        }
        printf("recv %d bytes\n",recv_len);
        hex_print(buf, recv_len);

        xqc_pktns_t * pktns = NULL;

        pktns = &conn->tlsref.hs_pktns;
        xqc_encrypt_t decrypt = NULL;
        if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0){
            decrypt = conn->tlsref.callbacks.decrypt;
        }else{
            pktns = & conn->tlsref.initial_pktns;
            if(pktns->rx_ckm.key.base != NULL && pktns->rx_ckm.key.len > 0){
                decrypt = conn->tlsref.callbacks.in_decrypt;
            }else{
                printf("error recv_handshake data \n");
                return -1;
            }
        }


        unsigned char * pkt_header = buf;
        unsigned char * encrypt_data = pkt_header + TEST_PKT_HEADER_LEN;

        uint8_t nonce[32];
        xqc_crypto_km_t *p_ckm = & pktns->rx_ckm;
        //xqc_vec_t  * p_hp = & p_pktns->tx_hp;
        xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);

        printf("decrypt key:\n");
        hex_print(p_ckm->key.base, p_ckm->key.len);
        printf("nonce:\n");
        hex_print(nonce, p_ckm->iv.len);
        printf("aead:\n");
        hex_print(pkt_header, TEST_PKT_HEADER_LEN);

        size_t nwrite = decrypt(conn, recv_buf, buf_len, encrypt_data, recv_len - TEST_PKT_HEADER_LEN,  p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, pkt_header,TEST_PKT_HEADER_LEN, NULL);

        if(nwrite <= 0){
            printf("decrypt error:%d\n",nwrite);
            return nwrite;
        }

        //recv_client_initial(conn, &dcid, NULL);
        //xqc_recv_client_hello_derive_key(conn, &dcid);
        printf("decrypt %d bytes\n",nwrite);
        hex_print(buf, nwrite);
        conn->tlsref.callbacks.recv_crypto_data(conn, 0, recv_buf, nwrite, NULL);

        int ret = send_server_handshake(conn, &conn->tlsref.initial_pktns, conn->tlsref.callbacks.in_encrypt, p_client_addr);
        if(ret < 0){
            printf("send_server_handshake error:%d\n",ret);
            return -1;
        }
        ret = send_server_handshake(conn, &conn->tlsref.hs_pktns, conn->tlsref.callbacks.encrypt, p_client_addr);
        if(ret < 0){
            printf("send_server_handshake error:%d\n",ret);
            return -1;
        }

        if(conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
            break;
        }
    }

    return 1;
}


int run(xqc_connection_t *conn){
    char buf[2048];
    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);


    int n = recv_client_hello(conn, &g_client_addr, buf, sizeof(buf));
    //n = recv_client_hs_data(conn,  &g_client_addr, buf, sizeof(buf));
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
    xqc_ssl_init_config(&xs_config, g_key_file, g_cert_file);

    engine.ssl_ctx = xqc_create_server_ssl_ctx(&xs_config);
    xqc_connection_t conn;
    conn.version = XQC_QUIC_VERSION;
    xqc_tlsref_init(& conn.tlsref);
    xqc_server_tls_initial(&engine, &conn, &xs_config);
    conn.tlsref.server = 1;

    run(&conn);

}
