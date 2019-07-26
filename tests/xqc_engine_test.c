
#include <CUnit/CUnit.h>
#include "../include/xquic.h"
#include "../transport/xqc_transport.h"
#include "../transport/xqc_packet.h"
#include "../common/xqc_log.h"
#include "../transport/xqc_engine.h"
#include "../transport/xqc_cid.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_str.h"
#include "../common/xqc_timer.h"
#include "../transport/xqc_conn.h"
#include "../congestion_control/xqc_new_reno.h"
#include "../transport/xqc_packet_parser.h"


void xqc_test_engine_create()
{
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT);
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;

    engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;
}


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\x00\x00\x00\x01\x55\xAB\x3f\x12\x0a\xcd\xef\x00\x89\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"


int xqc_test_conn_create_notify(xqc_cid_t *cid, void *user_data)
{
    return XQC_OK;
}

int xqc_test_conn_close_notify(xqc_cid_t *cid, void *user_data)
{
    return XQC_OK;
}

ssize_t xqc_client_send(void *user_data, unsigned char *buf, size_t size)
{
    return 0;
}


void xqc_test_engine_packet_process()
{
    const struct sockaddr * local_addr = NULL;
    socklen_t local_addrlen = 0;
    const struct sockaddr * peer_addr = NULL;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER);
    CU_ASSERT(engine != NULL);
    engine->eng_callback.conn_callbacks.conn_create_notify = xqc_test_conn_create_notify;
    engine->eng_callback.conn_callbacks.conn_close_notify = xqc_test_conn_close_notify;    
    engine->eng_callback.write_socket = xqc_client_send;
    engine->eng_callback.cong_ctrl_callback = xqc_reno_cb;

    xqc_msec_t recv_time = xqc_now();

    xqc_int_t rc = xqc_engine_packet_process(engine, 
                         XQC_TEST_LONG_HEADER_PACKET_B, sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1, 
                         local_addr, local_addrlen, 
                         peer_addr, peer_addrlen, recv_time, NULL);
    //CU_ASSERT(rc == XQC_OK);

    /* get connection */
    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    rc = xqc_packet_parse_cid(&dcid, &scid, XQC_TEST_LONG_HEADER_PACKET_B, sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1);
    CU_ASSERT(rc == XQC_OK);

    xqc_connection_t *conn = xqc_engine_conns_hash_find(engine, &scid, 'd');
    CU_ASSERT(conn != NULL);

    /* set handshake completed */
    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;

    recv_time = xqc_now();
    rc = xqc_engine_packet_process(engine, 
                         XQC_TEST_SHORT_HEADER_PACKET_A, sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1, 
                         local_addr, local_addrlen, 
                         peer_addr, peer_addrlen, recv_time, NULL);
    //CU_ASSERT(rc == XQC_OK);

    xqc_engine_destroy(engine);
}



