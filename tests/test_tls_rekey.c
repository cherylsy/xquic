#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_cmake_config.h"
#include "include/xquic.h"
#include <event2/event.h>
#include <memory.h>
#include "xqc_tls_init.h"
#include "transport/crypto/xqc_tls_public.h"
#include "include/xquic_typedef.h"
#include "transport/xqc_conn.h"
#include "transport/crypto/xqc_tls_cb.h"
#include "transport/crypto/xqc_tls_if.h"


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
#define EARLY_PKT_TYPE 1
#define APP_PKT_TYPE 2
#define HANDSHAKE_PKT_TYPE (0xFF)

//session ticket
//in short head packet and frame type is fr_crypto
//for test do not judge the condition
int recv_session_ticket(xqc_connection_t * conn, char * buf, int recv_len){
    //char buf[1024*2];
    struct sockaddr_in g_client_addr;

    int len = sizeof(g_client_addr);
    //while(1){

        //int recv_len = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL );
        //printf("recv server hello len:%d\n", recv_len);
        //hex_print(buf,recv_len);

        xqc_pktns_t * pktns = NULL;

        pktns = &conn->tlsref.pktns;
        xqc_encrypt_t decrypt = conn->tlsref.callbacks.decrypt;

        unsigned char * pkt_header = buf;
        unsigned char * encrypt_data = pkt_header + TEST_PKT_HEADER_LEN;

        uint8_t nonce[XQC_NONCE_LEN];
        xqc_crypto_km_t *p_ckm = & pktns -> rx_ckm;
        //xqc_vec_t  * p_hp = & p_pktns->tx_hp;
        xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);
#if 0
        printf("decrypt key:\n");
        hex_print(p_ckm->key.base, p_ckm->key.len);
        printf("nonce:\n");
        hex_print(nonce, p_ckm->iv.len);
        printf("aead:\n");
        hex_print(pkt_header, TEST_PKT_HEADER_LEN);
#endif

        char decrypt_buf[2048];
        int nwrite = decrypt(conn, decrypt_buf, sizeof(decrypt_buf), encrypt_data, recv_len - TEST_PKT_HEADER_LEN,  p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, pkt_header,TEST_PKT_HEADER_LEN, NULL);
        if(nwrite < 0){
            printf("error decrypt data\n");
            return 0;
            //break;
        }
#if 0
        printf("decrypt %d bytes:\n", nwrite);
        hex_print(decrypt_buf, nwrite);
#endif

        conn->tlsref.callbacks.recv_crypto_data(conn, 0, decrypt_buf, nwrite, NULL);

        //break;
    //}
    return 0;
}

int send_data(xqc_connection_t * conn, xqc_crypto_km_t * ckm, char *data, int data_len , xqc_encrypt_t encrypt_func, uint8_t pkt_type ){
    unsigned char send_buf[1024*2];
    uint8_t nonce[XQC_NONCE_LEN];
    unsigned char * pkt_header = send_buf;
    unsigned char * pkt_data = pkt_header + TEST_PKT_HEADER_LEN ;
    init_pkt_header(pkt_header,  TEST_PKT_HEADER_LEN);
    pkt_header[0] = pkt_type;
    pkt_header[1] = ckm->flags;

    xqc_crypto_km_t *p_ckm = ckm;
    //xqc_vec_t  * p_hp = early_hp;
    memcpy(pkt_data, data, data_len);
    xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);

    printf("encryp data key:\n");
    hex_print(p_ckm->key.base, p_ckm->key.len);

    size_t nwrite = encrypt_func(conn, pkt_data, sizeof(send_buf) - TEST_PKT_HEADER_LEN, pkt_data, data_len, p_ckm->key.base, p_ckm->key.len, nonce,p_ckm->iv.len, pkt_header, TEST_PKT_HEADER_LEN, NULL);
    int ret =  sendto(g_sock, send_buf, nwrite + TEST_PKT_HEADER_LEN, 0, (const void *)( &g_server_addr ), sizeof(g_server_addr));
    printf("client send data:%d\n", nwrite + TEST_PKT_HEADER_LEN);
    hex_print(send_buf, nwrite + TEST_PKT_HEADER_LEN);

    if(ret < 0){
        printf("error send data:%d",ret);
        return -1;
    }

    return ret;
}

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

#if 0
            printf("encrypt key:\n");
            hex_print(p_ckm->key.base, p_ckm->key.len);
            printf("nonce:\n");
            hex_print(nonce, p_ckm->iv.len);
            printf("aead:\n");
            hex_print(pkt_header, TEST_PKT_HEADER_LEN);

            printf("do encrypt %d bytes\n", buf->data_len);
            hex_print(pkt_data, buf->data_len);

#endif
            size_t nwrite = encrypt_func(conn, pkt_data, sizeof(send_buf) - TEST_PKT_HEADER_LEN, pkt_data, buf->data_len, p_ckm->key.base, p_ckm->key.len, nonce,p_ckm->iv.len, pkt_header, TEST_PKT_HEADER_LEN, NULL);

            if(nwrite <= 0){
                printf("error encrypt\n");
                return -1;
            }
#if 0
            printf("encrypt %d bytes\n", nwrite);
            hex_print(send_buf, nwrite + TEST_PKT_HEADER_LEN);
#endif
            int ret =  sendto(g_sock, send_buf, nwrite + TEST_PKT_HEADER_LEN, 0, (const void *)( &g_server_addr ), sizeof(g_server_addr));
            printf("client send data:%d\n", nwrite + TEST_PKT_HEADER_LEN);
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

int recv_data( xqc_connection_t *conn, struct sockaddr_in * p_client_addr){

    char recv_buf[2*2048];
    char buf[2*2048];
    int len = sizeof(struct sockaddr_in);
    while(1){
        int recv_len = recvfrom(g_sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *) p_client_addr, &len );
        if(recv_len < 0){
            return -1;
        }
        printf("recv %d bytes\n",recv_len);
        hex_print(recv_buf, recv_len);


        if(recv_buf[0] == APP_PKT_TYPE){
            //xqc_pktns_t * pktns = NULL;
            //pktns = &conn->tlsref.pktns;
        }else if(recv_buf[0] == HANDSHAKE_PKT_TYPE ){
            recv_session_ticket(conn, buf + TEST_PKT_HEADER_LEN, recv_len - TEST_PKT_HEADER_LEN);
            continue;
        }
        else{
            printf("read %d type data\n", buf[0]);

            continue;
        }

        if(recv_buf[1] != (conn->tlsref.pktns.rx_ckm.flags & XQC_CRYPTO_KM_FLAG_KEY_PHASE_ONE)?1:0 ){

            if(xqc_conn_prepare_key_update(conn) < 0){

                printf("update key error\n");
                return -1;
            }
            if(xqc_conn_commit_key_update(conn, 0) < 0){
                printf("update key error\n");
                return -1;
            }
        }

        if(conn->tlsref.flags & XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE){
           conn->tlsref.flags &= (uint16_t)~XQC_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE;
        }



        xqc_encrypt_t decrypt = NULL;
        decrypt = conn->tlsref.callbacks.decrypt;

        unsigned char * pkt_header = recv_buf;
        unsigned char * encrypt_data = pkt_header + TEST_PKT_HEADER_LEN;

        uint8_t nonce[XQC_NONCE_LEN];
        xqc_crypto_km_t *p_ckm = & conn->tlsref.pktns.rx_ckm;
        //xqc_vec_t  * p_hp = & p_pktns->tx_hp;
        //xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, p_ckm->pkt_num);
        xqc_crypto_create_nonce(nonce, p_ckm->iv.base, p_ckm->iv.len, 0); //not care about pkt_num , but pkt_num should be careful when doing integrated

        printf("decrypt  pkt num: %d, data key and iv key:\n", p_ckm->pkt_num);
        hex_print(p_ckm->key.base, p_ckm->key.len);
        hex_print(nonce, p_ckm->iv.len);


        int nwrite = decrypt(conn, buf, sizeof(buf), encrypt_data, recv_len - TEST_PKT_HEADER_LEN,  p_ckm->key.base, p_ckm->key.len, nonce, p_ckm->iv.len, pkt_header,TEST_PKT_HEADER_LEN, NULL);

        if(nwrite > 0){
        printf("decrypt %d bytes\n",nwrite);
        hex_print(buf, nwrite);
        }else{

            printf("decrypt error\n");
            return -1;
        }
        break;
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
#if 0
        printf("decrypt key:\n");
        hex_print(p_ckm->key.base, p_ckm->key.len);
        printf("nonce:\n");
        hex_print(nonce, p_ckm->iv.len);
        printf("aead:\n");
        hex_print(pkt_header, TEST_PKT_HEADER_LEN);
#endif
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


int run(xqc_connection_t * conn, xqc_cid_t *dcid){
    conn->tlsref.callbacks.client_initial(conn);

    char early_data[100] = "early data for test";

    send_buf_packet(conn , &conn->tlsref.initial_pktns,  conn->tlsref.callbacks.in_encrypt );

    send_data(conn, &conn->tlsref.early_ckm, early_data, strlen(early_data), conn->tlsref.callbacks.in_encrypt, EARLY_PKT_TYPE);

    recv_server_hello(conn);

    send_buf_packet(conn, &conn->tlsref.hs_pktns, conn->tlsref.callbacks.encrypt);

    //recv_session_ticket(conn);
    printf("Negotiated cipher suite is:%s\n",SSL_get_cipher_name(conn->xc_ssl));

    int send_num = 0;
    while(send_num++ < 10){
        char send_buf[100];
        int send_len = snprintf(send_buf, sizeof(send_buf), "send data num:%d",send_num);
        send_data(conn, &conn->tlsref.pktns.tx_ckm, send_buf, send_len, conn->tlsref.callbacks.in_encrypt, APP_PKT_TYPE);

        recv_data(conn, &g_server_addr);
        if(send_num == 5){
           xqc_start_key_update(conn);
        }
    }
    return 0;
}



int main(int argc, char *argv[]){

    DEBUG
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);

    char session_path[256] = {0};
    char tp_path[256] = {0};
    int ch = 0;
    while((ch = getopt(argc, argv, "a:p:s:t:")) != -1){
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
            case 's':
                snprintf(session_path, sizeof(session_path), optarg);
                break;
            case 't':
                snprintf(tp_path, sizeof(tp_path), optarg);
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
    if(strlen(session_path) > 0 && strlen(tp_path) > 0){
        xs_config.session_path = session_path;
        xs_config.tp_path = tp_path;
    }

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

    close(g_sock);

}
