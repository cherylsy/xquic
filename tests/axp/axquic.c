#include "axquic.h"

axquic_data_buf_t * xqc_create_data_buf(int buf_size){

    axquic_data_buf_t * p_buf = malloc(sizeof(axquic_data_buf_t) + buf_size);
    if(p_buf == NULL)return NULL;
    xqc_init_list_head(&p_buf->list_head);
    p_buf->buf_len = p_buf->data_len = buf_size;
    p_buf->already_consume = 0;
    p_buf->fin = 0;
    return p_buf;
}

int axquic_free_data_buf( xqc_list_head_t * head_list){
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head_list){
        xqc_list_del(pos);
        free(pos);
    }
    return 0;
}

int axquic_buf_to_tail(xqc_list_head_t * phead , char * data, int data_len, uint8_t fin){

    axquic_data_buf_t * p_buf = xqc_create_data_buf(data_len);
    if(p_buf == NULL){
        return -1;
    }

    memcpy(p_buf->data, data, data_len);

    p_buf->fin = fin;
    xqc_list_add_tail(&p_buf->list_head, phead);
    return 0;
}

xqc_engine_t *  axquic_client_initial_engine(xqc_engine_callback_t callback, xqc_conn_settings_t conn_setting, void * user_data){

    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = NULL;
    engine_ssl_config.cert_file = NULL;
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_ssl_config, callback, conn_setting, user_data);

    if(engine == NULL){
        return NULL;
    }
    return engine;
}


xqc_engine_t * axquic_server_initial_engine( xqc_engine_callback_t callback, xqc_conn_settings_t conn_setting,
        char * session_ticket_key, int ticket_key_len, char * private_key_file, char * cert_file, void * user_data){

    xqc_engine_ssl_config_t engine_ssl_config;
    engine_ssl_config.private_key_file = private_key_file;
    engine_ssl_config.cert_file = cert_file;
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    if(ticket_key_len < 0){
        engine_ssl_config.session_ticket_key_len = 0;
        engine_ssl_config.session_ticket_key_data = NULL;
    }else{
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
        engine_ssl_config.session_ticket_key_data = session_ticket_key;
    }

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER, &engine_ssl_config, callback, conn_setting, user_data);

    if(engine == NULL){
        return NULL;
    }

    return engine;

}

xqc_cid_t * axquic_connect(xqc_engine_t *engine, void * user_data, char * server_addr,
        uint16_t server_port, uint8_t * token, int token_len,
        uint8_t * session_ticket_data, int session_ticket_len,
        uint8_t * transport_parameter_data, int transport_parameter_data_len,
        struct sockaddr *peer_addr, socklen_t peer_addrlen){

    xqc_conn_ssl_config_t conn_ssl_config;
    if(session_ticket_len < 0 || transport_parameter_data_len < 0){
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;
    }else{
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_ticket_len;
        conn_ssl_config.transport_parameter_data = transport_parameter_data;
        conn_ssl_config.transport_parameter_data_len = transport_parameter_data_len;
    }

    uint8_t no_crypto_flag = 0;
    xqc_cid_t *cid = xqc_connect(engine, user_data, token, token_len, server_addr, no_crypto_flag, &conn_ssl_config, peer_addr, peer_addrlen);
    if(cid == NULL){
        return NULL;
    }

    return cid;
}



axquic_client_stream_t * axquic_open_stream(xqc_engine_t * engine, xqc_cid_t * cid){

    axquic_client_stream_t * c_stream = malloc(sizeof(axquic_client_stream_t));
    c_stream->cid = cid;
    c_stream->stream = xqc_stream_create(engine, cid, c_stream);
    xqc_init_list_head(&c_stream->send_frame_data_buf);
    return c_stream;
}


int axquic_send_stream_buf(axquic_client_stream_t * client_stream){

    xqc_list_head_t *head = &client_stream->send_frame_data_buf;
    xqc_list_head_t *pos, *next;
    axquic_data_buf_t * send_buf = NULL;
    int ret = 1;
    xqc_list_for_each_safe(pos, next, head){
        send_buf = xqc_list_entry(pos, axquic_data_buf_t, list_head);

        ssize_t send_success = xqc_stream_send(client_stream->stream, send_buf->data + send_buf->already_consume, send_buf->data_len - send_buf->already_consume, send_buf->fin);
        if (send_success < 0) {
            return send_success;
        }

        if(send_success + send_buf->already_consume != send_buf->data_len){
            send_buf->already_consume += send_success;
            ret = 0; // means send data not completely
            break;
        }else{
            xqc_list_del(pos);
            free(pos);
        }

    }
    return ret;

}


int axquic_send(axquic_client_stream_t * client_stream, char * data, int data_len, uint8_t fin){

    int ret = 0;

    axquic_buf_to_tail(&client_stream->send_frame_data_buf, data, data_len, fin);
    axquic_send_stream_buf(client_stream);

    return data_len;
}




int axquic_recv(axquic_client_stream_t * client_stream, uint8_t *buffer, size_t len, uint8_t *fin){
    return xqc_stream_recv(client_stream->stream, buffer, len, fin);

}

int axquic_packet_process (xqc_engine_t *engine,
                               const unsigned char *packet_in_buf,
                               size_t packet_in_size,
                               const struct sockaddr *local_addr,
                               socklen_t local_addrlen,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen,
                               xqc_msec_t recv_time,
                               void *user_data){


    return xqc_engine_packet_process(engine, packet_in_buf, packet_in_size, local_addr, local_addrlen,
            peer_addr, peer_addrlen, recv_time, user_data);
}



