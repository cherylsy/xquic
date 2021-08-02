#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xquic/xquic.h"
#include <event2/event.h>
#include <memory.h>
#include "src/crypto/xqc_tls_init.h"
#include "src/crypto/xqc_tls_public.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_conn.h"



static char server_addr[256] = {0};
unsigned short server_port = 0;
unsigned long DCID_TEST = 0x1234567812345678;
int                 g_sock;
struct sockaddr_in  g_server_addr;


#define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);


int init_pkt_header(unsigned char * dest, int n){
    int i = 0;
    for(i = 0; i < n ; i++){
        dest[i] = 0xff;
    }

    return 0;
}

#define TEST_PKT_HEADER_LEN 16
int send_buf_packet( xqc_connection_t * conn, xqc_pktns_t * p_pktns , xqc_encrypt_t encrypt_func ){
    xqc_list_head_t *head = &p_pktns->msg_cb_head;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos,next, head){
        xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
        if(buf->data_len > 0){
            unsigned char send_buf[1024*2];
            unsigned char * pkt_header = send_buf;
            unsigned char * pkt_data = pkt_header + TEST_PKT_HEADER_LEN ;
            init_pkt_header(pkt_header,  TEST_PKT_HEADER_LEN);

            //uint64_t pkt_num = 0;
            uint8_t nonce[XQC_NONCE_LEN];
            xqc_crypto_km_t *p_ckm = & p_pktns->tx_ckm;
            xqc_vec_t  * p_hp = & p_pktns->tx_hp;
            memcpy(pkt_data, buf->data, buf->data_len);
            xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);

            printf("do encrypt %zu bytes\n", buf->data_len);
            hex_print(pkt_data, buf->data_len);

            size_t nwrite = encrypt_func(conn, pkt_data, sizeof(send_buf) - TEST_PKT_HEADER_LEN, pkt_data, buf->data_len, p_ckm->key.base, p_ckm->key.len, nonce,p_ckm->iv.len, pkt_header, TEST_PKT_HEADER_LEN, NULL);

            if(nwrite <= 0){
                printf("error encrypt\n");
                return -1;
            }

            int ret =  sendto(g_sock, send_buf, nwrite + TEST_PKT_HEADER_LEN, 0, (const void *)( &g_server_addr ), sizeof(g_server_addr));
            printf("client send data:%lu\n", nwrite + TEST_PKT_HEADER_LEN);
            hex_print(send_buf, nwrite + TEST_PKT_HEADER_LEN);

            buf->data_len  = 0;
            if(ret < 0){
                printf("error send data:%d",ret);
                return -1;
            }
        }

        xqc_list_del(pos);
        free(pos);
    }
    return 0;
}


int recv_server_hello(xqc_connection_t * conn){
    char buf[1024*2];
    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);
    while(1){


        int recv_len = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL );
        printf("recv server hello len:%d\n", recv_len);
        hex_print(buf,recv_len);

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

        uint8_t nonce[XQC_NONCE_LEN];
        xqc_crypto_km_t *p_ckm = & pktns -> rx_ckm;
        //xqc_vec_t  * p_hp = & p_pktns->tx_hp;
        xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);

        char decrypt_buf[2048];
        int nwrite = decrypt(conn, decrypt_buf, sizeof(decrypt_buf), encrypt_data, recv_len - TEST_PKT_HEADER_LEN,  p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, pkt_header,TEST_PKT_HEADER_LEN, NULL);
        if(nwrite < 0){
            printf("error decrypt data\n");
            break;
        }

        conn->tlsref.callbacks.recv_crypto_data(conn, 0, decrypt_buf, nwrite, NULL);
        if (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
            break;
        }
    }
    return 0;
}

//session ticket
//in short head packet and frame type is fr_crypto
//for test do not judge the condition
int recv_session_ticket(xqc_connection_t * conn){
    char buf[1024*2];
    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);
    while(1){

        int recv_len = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL );
        printf("recv server hello len:%d\n", recv_len);
        hex_print(buf,recv_len);

        xqc_pktns_t * pktns = NULL;

        pktns = &conn->tlsref.pktns;
        xqc_encrypt_t decrypt = conn->tlsref.callbacks.decrypt;

        unsigned char * pkt_header = buf;
        unsigned char * encrypt_data = pkt_header + TEST_PKT_HEADER_LEN;

        uint8_t nonce[XQC_NONCE_LEN];
        xqc_crypto_km_t *p_ckm = & pktns -> rx_ckm;
        //xqc_vec_t  * p_hp = & p_pktns->tx_hp;
        xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);

        char decrypt_buf[2048];
        int nwrite = decrypt(conn, decrypt_buf, sizeof(decrypt_buf), encrypt_data, recv_len - TEST_PKT_HEADER_LEN,  p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, pkt_header,TEST_PKT_HEADER_LEN, NULL);
        if(nwrite < 0){
            printf("error decrypt data\n");
            break;
        }
        printf("decrypt %d bytes:\n", nwrite);
        hex_print(decrypt_buf, nwrite);


        conn->tlsref.callbacks.recv_crypto_data(conn, 0, decrypt_buf, nwrite, NULL);

#if 0
        if (conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
            break;
        }
#endif
    }
    return 0;
}





int run(xqc_connection_t * conn, xqc_cid_t *dcid){
    conn->tlsref.callbacks.client_initial(conn);

    send_buf_packet(conn , &conn->tlsref.initial_pktns,  conn->tlsref.callbacks.in_encrypt );

    recv_server_hello(conn);

    send_buf_packet(conn, &conn->tlsref.hs_pktns, conn->tlsref.callbacks.encrypt);

    recv_session_ticket(conn);
    printf("Negotiated cipher suite is:%s\n",SSL_get_cipher_name(conn->xc_ssl));

    return 0;
}

int main(int argc, char *argv[]){

    DEBUG
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

    if(strlen(server_addr) == 0 ||  server_port == 0) {
        printf("server address error,check argment");
        exit(0);
    }
    g_server_addr.sin_family = AF_INET;
    g_server_addr.sin_port = htons(server_port);
    (void)inet_aton((void *)server_addr, &g_server_addr.sin_addr);

    xqc_engine_t  engine;
    xqc_ssl_config_t xs_config;
    xqc_ssl_init_config(&xs_config, NULL, NULL, NULL);
    //CU_ASSERT(0 != strcmp(xs_config.ciphers, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"));


    int no_crypto_flag = 0; // 1 means no crypto

    engine.ssl_ctx = xqc_create_client_ssl_ctx(&xs_config);
    //CU_ASSERT( engine.ssl_ctx != NULL);

    xqc_connection_t conn;
    xqc_cid_t dcid;
    memcpy(dcid.cid_buf, &DCID_TEST, sizeof(DCID_TEST));
    dcid.cid_len = sizeof(DCID_TEST);
    //xqc_create_client_ssl(&engine, &conn,  server_addr,
    xqc_client_tls_initial(&engine, &conn, server_addr, &xs_config, &dcid, no_crypto_flag);

    int rc = xqc_client_setup_initial_crypto_context(&conn, &dcid);
    //CU_ASSERT( rc == 0);

    conn.version = XQC_VERSION_V1;
    run(&conn, &dcid);


}
