#include <common/xqc_errno.h>
#include "xqc_conn.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_transport.h"
#include "xqc_packet_out.h"
#include "xqc_send_ctl.h"
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"

#define XQC_STREAM_BUFF_MAX 1024*1024

static xqc_stream_id_t
xqc_gen_stream_id (xqc_connection_t *conn, xqc_stream_id_type_t type)
{
    xqc_stream_id_t sid;
    if (type == XQC_CLI_BID || type == XQC_SVR_BID) {
        sid = conn->cur_stream_id_bidi_local++;
    } else if (type == XQC_CLI_UNI || type ==XQC_SVR_UNI) {
        sid = conn->cur_stream_id_uni_local++;
    }

    sid = sid << 2 | type;
    return sid;
}

void
xqc_stream_ready_to_write (xqc_stream_t *stream)
{
    if (!(stream->stream_flag & XQC_SF_READY_TO_WRITE)) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_add_tail(&stream->write_stream_list, &stream->stream_conn->conn_write_streams);
        }
        stream->stream_flag |= XQC_SF_READY_TO_WRITE;
    }

    if (!(stream->stream_conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (xqc_conns_pq_push(stream->stream_conn->engine->conns_pq,
                          stream->stream_conn, stream->stream_conn->last_ticked_time) != 0) {
            return;
        }
        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_TICKING;
    }
}

void
xqc_stream_shutdown_write (xqc_stream_t *stream)
{
    if (stream->stream_flag & XQC_SF_READY_TO_WRITE) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_del_init(&stream->write_stream_list);
        }
        stream->stream_flag &= ~XQC_SF_READY_TO_WRITE;
    }
}

void
xqc_stream_ready_to_read (xqc_stream_t *stream)
{
    if (!(stream->stream_flag & XQC_SF_READY_TO_READ)) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_add_tail(&stream->read_stream_list, &stream->stream_conn->conn_read_streams);
        }
        stream->stream_flag |= XQC_SF_READY_TO_READ;
    }

    if (!(stream->stream_conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (xqc_conns_pq_push(stream->stream_conn->engine->conns_pq,
                              stream->stream_conn, stream->stream_conn->last_ticked_time) != 0) {
            return;
        }
        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_TICKING;
    }

}

void
xqc_stream_shutdown_read (xqc_stream_t *stream)
{
    if (stream->stream_flag & XQC_SF_READY_TO_READ) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_del_init(&stream->read_stream_list);
        }
        stream->stream_flag &= ~XQC_SF_READY_TO_READ;
    }
}

xqc_stream_t *
xqc_find_stream_by_id (xqc_stream_id_t stream_id, xqc_id_hash_table_t *streams_hash)
{
    xqc_stream_t *stream = xqc_id_hash_find(streams_hash, stream_id);
    return stream;
}

static void
xqc_stream_set_flow_ctl (xqc_stream_t *stream, xqc_trans_param_t *trans_param)
{
    if (stream->stream_id_type == XQC_CLI_BID) {
        stream->stream_flow_ctl.fc_max_stream_data = trans_param->initial_max_stream_data_bidi_local;
    } else if (stream->stream_id_type == XQC_SVR_BID) {
        stream->stream_flow_ctl.fc_max_stream_data = trans_param->initial_max_stream_data_bidi_remote;
    } else {
        stream->stream_flow_ctl.fc_max_stream_data = trans_param->initial_max_stream_data_uni;
    }
}

int
xqc_stream_do_flow_ctl(xqc_stream_t *stream)
{
    if (stream->stream_conn->conn_flow_ctl.fc_data_sent >= stream->stream_conn->conn_flow_ctl.fc_max_data) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_stream_send|exceed max_data|%d|",
                stream->stream_conn->conn_flow_ctl.fc_max_data);

        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_DATA_BLOCKED;
        xqc_write_data_blocked_to_packet(stream->stream_conn, stream->stream_conn->conn_flow_ctl.fc_max_data);
        return 1;
    }

    if (stream->stream_send_offset >= stream->stream_flow_ctl.fc_max_stream_data) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_stream_send|exceed max_stream_data|%d|",
                stream->stream_flow_ctl.fc_max_stream_data);

        stream->stream_flag |= XQC_SF_STREAM_DATA_BLOCKED;
        xqc_write_stream_data_blocked_to_packet(stream->stream_conn, stream->stream_id,
                                                stream->stream_flow_ctl.fc_max_stream_data);
        return 1;
    }
    return 0;
}

xqc_stream_t *
xqc_create_stream (xqc_engine_t *engine,
                   xqc_cid_t *cid,
                  void *user_data)
{
    xqc_connection_t *conn;
    xqc_stream_t *stream;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_create_stream|can not find connection");
        return NULL;
    }

    stream = xqc_create_stream_with_conn(conn, user_data);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_create_stream|can not find connection");
        return NULL;
    }

    xqc_engine_main_logic(engine);
    return stream;
}

xqc_stream_t *
xqc_create_stream_with_conn (xqc_connection_t *conn,
                            void *user_data)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_create_stream cur_stream_id_bidi_local=%ui",
            conn->cur_stream_id_bidi_local);

    if (conn->cur_stream_id_bidi_local >= conn->conn_flow_ctl.fc_max_streams_bidi) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_stream|exceed max_streams_bidi|%d|",
                conn->conn_flow_ctl.fc_max_streams_bidi);
        xqc_write_streams_blocked_to_packet(conn, conn->conn_flow_ctl.fc_max_streams_bidi, 1);
        return NULL;
    }

    xqc_stream_t *stream = xqc_calloc(1, sizeof(xqc_stream_t));
    if (stream == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_stream|xqc_pcalloc error|");
        return NULL;
    }
    xqc_list_add_tail(&stream->all_stream_list, &conn->conn_all_streams);

    stream->stream_encrypt_level = XQC_ENC_LEV_1RTT;

    stream->stream_conn = conn;
    stream->stream_if = &conn->engine->eng_callback.stream_callbacks;
    stream->user_data = user_data;
    stream->stream_state_send = XQC_SSS_READY;
    stream->stream_state_recv = XQC_RSS_RECV;

    xqc_stream_set_flow_ctl(stream, &conn->trans_param);

    xqc_init_list_head(&stream->stream_data_in.frames_tailq);

    xqc_init_list_head(&stream->stream_write_buff_list.write_buff_list);

    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        stream->stream_id_type = XQC_CLI_BID;
        stream->stream_id = xqc_gen_stream_id(conn, stream->stream_id_type);
        xqc_id_hash_element_t e = {stream->stream_id, stream};
        if (xqc_id_hash_add(conn->streams_hash, e)) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_stream|xqc_id_hash_add error|");
            goto error;
        }
        xqc_stream_ready_to_write(stream);
    } else {
        stream->stream_id_type = XQC_SVR_BID;
    }

    return stream;

error:
    xqc_list_del_init(&stream->all_stream_list);
    xqc_free(stream);
    return NULL;
}

void
xqc_destroy_stream(xqc_stream_t *stream)
{
    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "xqc_destroy_stream send_state:%ui, recv_state: %ui",
            stream->stream_state_send, stream->stream_state_recv);
    xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq);

    xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);

    xqc_free(stream);
}

xqc_stream_t *
xqc_server_create_stream (xqc_connection_t *conn, xqc_stream_id_t stream_id,
                   void *user_data)
{
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, user_data);
    if (stream == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_server_create_stream|xqc_create_stream error|");
        return NULL;
    }

    stream->stream_id = stream_id;
    xqc_id_hash_element_t e = {stream->stream_id, stream};
    if (xqc_id_hash_add(conn->streams_hash, e)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_server_create_stream|xqc_id_hash_add error|");
        return NULL;
    }
    return stream;
}

int xqc_read_crypto_stream(xqc_stream_t * stream){

    xqc_list_head_t *pos, *next;

    xqc_stream_frame_t * stream_frame = NULL;

    xqc_connection_t *conn = stream->stream_conn;
    xqc_list_for_each_safe(pos, next, &stream->stream_data_in.frames_tailq) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if(stream->stream_data_in.next_read_offset < stream_frame->data_offset){
            break;
        }

        if(stream->stream_data_in.next_read_offset >= stream_frame->data_offset + stream_frame->data_length){
            xqc_list_del(pos);
            xqc_destroy_stream_frame(stream_frame);
            continue;
        }

        size_t data_len  = stream_frame->data_offset  + stream_frame->data_length - stream->stream_data_in.next_read_offset;
        char * data_start =  stream_frame->data + (stream->stream_data_in.next_read_offset - stream_frame->data_offset);

        //printf("recv crypto data:%d\n",data_len);
        //hex_print(data_start, data_len);
        int ret = conn->tlsref.callbacks.recv_crypto_data(conn, 0, data_start, data_len, NULL);

        xqc_list_del(pos);
        xqc_destroy_stream_frame(stream_frame);

        stream->stream_data_in.next_read_offset = stream->stream_data_in.next_read_offset + data_len;
        if(ret < 0){
            return ret;
        }
    }

    return 0;
}


int xqc_crypto_stream_on_read (xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_pkt_type_t pkt_type;
    xqc_encrypt_level_t encrypt_level = stream->stream_encrypt_level;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    xqc_conn_state_t next_state;

    xqc_connection_t * conn = stream->stream_conn;

    if (encrypt_level == XQC_ENC_LEV_INIT) {
        switch (cur_state) {
            case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
                next_state = XQC_CONN_STATE_CLIENT_INITIAL_RECVD;
                break;
            case XQC_CONN_STATE_SERVER_INIT:
                xqc_stream_ready_to_write(stream);
                next_state = XQC_CONN_STATE_SERVER_INITIAL_RECVD;
                break;
            default:
                next_state = cur_state;
        }
    } else if (encrypt_level == XQC_ENC_LEV_HSK) {
        switch (cur_state) {
            case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
            case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
            case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
                xqc_stream_ready_to_write(stream);
                next_state = XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD;
                break;

            case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
            case XQC_CONN_STATE_SERVER_INITIAL_SENT:
                xqc_stream_ready_to_write(stream);
                next_state = XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD;
                break;
            case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
                next_state = XQC_CONN_STATE_ESTABED;
                if(conn->crypto_stream[XQC_ENC_LEV_1RTT] != NULL){
                   xqc_stream_ready_to_write(conn->crypto_stream[XQC_ENC_LEV_1RTT]);
                }
                break;
            default:
                next_state = cur_state;
        }
    }else if (encrypt_level == XQC_ENC_LEV_1RTT){

        switch (cur_state) {

            case XQC_CONN_STATE_ESTABED:
                next_state = XQC_CONN_STATE_ESTABED;
                break;
            default:
                xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "xqc_crypto_stream_on_read illegal encrypt_level %d",
                        encrypt_level);
                return -XQC_ELEVEL;
        }
    }else {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "xqc_crypto_stream_on_read illegal encrypt_level %d",
                encrypt_level);
        return -XQC_ELEVEL;
    }

    stream->stream_conn->conn_state = next_state;

    if (next_state == XQC_CONN_STATE_ESTABED && conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX) {
        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    }

    xqc_stream_shutdown_read(stream);

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG,
            "xqc_crypto_stream_on_read encrypt_level=%d, cur_state=%s, next_state=%s",
            encrypt_level, xqc_conn_state_2_str(cur_state), xqc_conn_state_2_str(next_state));
    return 0;
}

#define MIN_CRYPTO_FRAME_SIZE 8
int xqc_crypto_stream_send( xqc_stream_t *stream, xqc_pktns_t *  p_pktns, xqc_encrypt_t encrypt_func, xqc_pkt_type_t pkt_type  ){

    if(p_pktns == NULL){
        return 0;
    }
    size_t send_data_written = 0;
    int n_written = 0;
    xqc_packet_out_t *packet_out;
    xqc_connection_t *c = stream->stream_conn;

    xqc_list_head_t *head = &p_pktns->msg_cb_head;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos,next, head){
        xqc_hs_buffer_t *buf = (xqc_hs_buffer_t *)pos;
        //printf("send crypto data:%d\n", buf->data_len);
        //hex_print(buf->data, buf->data_len);
        if(buf->data_len > 0){
            int send_data_num =  stream->stream_send_offset + buf->data_len;
            size_t offset = 0;
            while (stream->stream_send_offset < send_data_num) {
                unsigned int header_size = xqc_crypto_frame_header_size(stream->stream_send_offset,
                        buf->data_len - offset);

                int need = 0;
                need = ((buf->data_len - offset + header_size) > XQC_PACKET_OUT_SIZE) ?(header_size + MIN_CRYPTO_FRAME_SIZE):( buf->data_len - offset + header_size);
                packet_out = xqc_write_packet(c, pkt_type, header_size + MIN_CRYPTO_FRAME_SIZE);
                if (packet_out == NULL) {
                    return -XQC_ENULLPTR;
                }

                //printf("crypt send packet_out:%p\n", packet_out);
                n_written = xqc_gen_crypto_frame(packet_out,
                        stream->stream_send_offset,
                        buf->data + offset,
                        buf->data_len - offset,
                        &send_data_written);
                //printf("send data written :%d\n", send_data_written);
                if (n_written < 0) {
                    return n_written;
                }
                offset += send_data_written;
                stream->stream_send_offset += send_data_written;
                packet_out->po_used_size += n_written;

                xqc_long_packet_update_length(packet_out);
            }
        }
        xqc_list_del(pos);
        free(pos);
    }

    return 0;

}

int xqc_crypto_stream_on_write (xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    int ret;

    xqc_pkt_num_space_t pns;
    xqc_pkt_type_t pkt_type;
    xqc_encrypt_level_t encrypt_level = stream->stream_encrypt_level;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    xqc_conn_state_t next_state;

    xqc_connection_t * conn = stream->stream_conn;

    xqc_pktns_t *  p_pktns = NULL;


    if (encrypt_level == XQC_ENC_LEV_INIT) {
        pns = XQC_PNS_INIT;
        pkt_type = XQC_PTYPE_INIT;
        switch (cur_state) {
            case XQC_CONN_STATE_CLIENT_INIT:
                conn->tlsref.callbacks.client_initial(conn);
                p_pktns = &conn->tlsref.initial_pktns;
                next_state = XQC_CONN_STATE_CLIENT_INITIAL_SENT;
                break;
            case XQC_CONN_STATE_SERVER_INIT:
            case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
                p_pktns = &conn->tlsref.initial_pktns;
                if(conn->crypto_stream[XQC_ENC_LEV_HSK] != NULL){
                   xqc_stream_ready_to_write(conn->crypto_stream[XQC_ENC_LEV_HSK]);
                }

                next_state = XQC_CONN_STATE_SERVER_INITIAL_SENT;
                break;
            default:
                next_state = cur_state;
        }
    } else if (encrypt_level == XQC_ENC_LEV_HSK) {
        pns = XQC_PNS_HSK;
        pkt_type = XQC_PTYPE_HSK;
        switch (cur_state) {
            case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
                p_pktns = &conn->tlsref.hs_pktns;
                if(conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
                    next_state = XQC_CONN_STATE_ESTABED;
                }else{
                    next_state = cur_state;
                }

                break;
            case XQC_CONN_STATE_SERVER_INITIAL_SENT:
            case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
                p_pktns = &conn->tlsref.hs_pktns;
                next_state = XQC_CONN_STATE_SERVER_HANDSHAKE_SENT;
                break;
            default:
                next_state = cur_state;
        }
    } else if (encrypt_level == XQC_ENC_LEV_1RTT) {
        pkt_type = XQC_PTYPE_SHORT_HEADER;
        switch (cur_state) {
            case XQC_CONN_STATE_ESTABED:
                p_pktns = &conn->tlsref.pktns;
                next_state = cur_state;
                break;
            default:
                xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "xqc_crypto_stream_on_write illegal encrypt_level %d",
                        encrypt_level);
                return -XQC_ELEVEL;
        }
    }

    else {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "xqc_crypto_stream_on_write illegal encrypt_level %d",
                encrypt_level);
        return -XQC_ELEVEL;
    }

    if(p_pktns != NULL){
        xqc_crypto_stream_send(stream, p_pktns, NULL, pkt_type );
    }


    xqc_stream_shutdown_write(stream);

    stream->stream_conn->conn_state = next_state;
#if 0
    if (next_state == XQC_CONN_STATE_ESTABED ||
            next_state == XQC_CONN_STATE_SERVER_HANDSHAKE_SENT ||
            next_state == XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT) {
#endif
    if (next_state == XQC_CONN_STATE_ESTABED && conn->tlsref.flags & XQC_CONN_FLAG_HANDSHAKE_COMPLETED_EX){
        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    }//????????????????????????
    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG,
            "xqc_crypto_stream_on_write encrypt_level=%d, cur_state=%s, next_state=%s",
            encrypt_level, xqc_conn_state_2_str(cur_state), xqc_conn_state_2_str(next_state));
    return 0;
}

xqc_stream_callbacks_t crypto_stream_callback = {
        .stream_read_notify = xqc_crypto_stream_on_read,
        .stream_write_notify = xqc_crypto_stream_on_write,
};

xqc_stream_t *
xqc_create_crypto_stream (xqc_connection_t *conn,
                          xqc_encrypt_level_t encrypt_level,
                          void *user_data)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_create_crypto_stream encrypt_level=%d, cur_state=%s",
            encrypt_level, xqc_conn_state_2_str(conn->conn_state));

    xqc_stream_t *stream = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    memset(stream, 0 ,sizeof(xqc_stream_t));

    stream->stream_id_type = XQC_CLI_BID;
    stream->stream_encrypt_level = encrypt_level;
    stream->stream_conn = conn;
    stream->stream_if = &crypto_stream_callback;
    stream->user_data = user_data;

    xqc_init_list_head(&stream->stream_data_in.frames_tailq);

    if(!conn->tlsref.server){
        xqc_stream_ready_to_write(stream);
    }

    return stream;
}


ssize_t xqc_stream_recv (xqc_stream_t *stream,
                         unsigned char *recv_buf,
                         size_t recv_buf_size,
                         uint8_t *fin)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_frame_t *stream_frame = NULL;
    size_t read = 0;
    size_t frame_left;
    *fin = 0;

    if (stream->stream_state_recv >= XQC_RSS_RESET_RECVD) {
        return -XQC_ESTREAM_ST;
    }

    xqc_list_for_each_safe(pos, next, &stream->stream_data_in.frames_tailq) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        /*printf("data_offset: %llu, data_length: %u, next_read_offset: %llu\n",
               stream_frame->data_offset, stream_frame->data_length, stream_frame->next_read_offset);*/

        if (stream_frame->data_offset > stream->stream_data_in.merged_offset_end) {
            break;
        }

        if (read >= recv_buf_size) {
            break;
        }

        frame_left = stream_frame->data_length - stream_frame->next_read_offset;

        if (read + frame_left <= recv_buf_size) {
            memcpy(recv_buf + read, stream_frame->data + stream_frame->next_read_offset, frame_left);
            stream->stream_data_in.next_read_offset += frame_left;
            stream_frame->next_read_offset = stream_frame->data_length;
            read += frame_left;
            //free frame
            xqc_list_del_init(&stream_frame->sf_list);
            xqc_free(stream_frame->data);
            xqc_free(stream_frame);
        } else {
            memcpy(recv_buf + read, stream_frame->data + stream_frame->next_read_offset, recv_buf_size - read);
            stream_frame->next_read_offset += recv_buf_size - read;
            stream->stream_data_in.next_read_offset += recv_buf_size - read;
            read = recv_buf_size;
            break;
        }

    }

    if (stream->stream_data_in.stream_length > 0 &&
        stream->stream_data_in.next_read_offset == stream->stream_data_in.stream_length) {
        *fin = 1; //TODO: free stream?
        if (stream->stream_state_recv == XQC_RSS_DATA_RECVD) {
            stream->stream_state_recv = XQC_RSS_DATA_READ;
        }
    }

    xqc_stream_shutdown_read(stream);
    return read;
}



ssize_t
xqc_stream_send (xqc_stream_t *stream,
                 unsigned char *send_data,
                 size_t send_data_size,
                 uint8_t fin)
{
    int ret;
    size_t send_data_written = 0;
    size_t offset = 0; //本次send_data中的已写offset
    xqc_connection_t *conn = stream->stream_conn;
    xqc_packet_out_t *packet_out;
    uint8_t fin_only = fin && !send_data_size;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    int support_0rtt = xqc_is_ready_to_send_early_data(conn);

    int buff_1rtt = 0;

    if (!(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)) {
        if((conn->tlsref.server == XQC_CLIENT) && (conn->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT)  &&
            support_0rtt){
            pkt_type = XQC_PTYPE_0RTT;
        }else{
            buff_1rtt = 1;
        }
    }

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    if (stream->stream_state_send > XQC_SSS_SEND) {
        return -XQC_ESTREAM_ST;
    }

    while (offset < send_data_size || fin_only) {

        if (xqc_stream_do_flow_ctl(stream)) {
            goto do_buff;
        }

        if (!xqc_send_ctl_can_write(conn->conn_send_ctl)) {
            goto do_buff;
        }

        if (pkt_type == XQC_PTYPE_0RTT && conn->zero_rtt_count > XQC_PACKET_0RTT_MAX_COUNT) {
            goto do_buff;
        }

        ret = xqc_write_stream_frame_to_packet(conn, stream, pkt_type,
                                               fin,
                                               send_data + offset,
                                               send_data_size - offset,
                                               &send_data_written);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stream_frame_to_packet error|");
            return ret;
        }

        offset += send_data_written;
        fin_only = 0;
    }

    xqc_stream_shutdown_write(stream);

do_buff:
    /* 握手完成后再发送，移到缓存包队列 */
    if (buff_1rtt) {
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_send_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_SHORT_HEADER) {
                xqc_send_ctl_remove_send(&packet_out->po_list);
                xqc_send_ctl_insert_buff(&packet_out->po_list, &conn->conn_send_ctl->ctl_buff_packets);
                if (!(conn->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
                    packet_out->po_flag |= XQC_POF_DCID_NOT_DONE;
                }
            }
        }
    }

    /* 0RTT失败需要回退到1RTT，保存原始发送数据 */
    if (pkt_type == XQC_PTYPE_0RTT) {
        /* fin还未写入packet */
        if (offset != send_data_size && fin) {
            fin = 0;
        }

        /* 如果没有写入任何数据或fin，则不需要缓存 */
        if (offset > 0 || fin_only) {
            xqc_stream_write_buff(stream, send_data, offset, fin);
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_stream_send|offset=%ui|", stream->stream_send_offset);


    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }
    xqc_engine_main_logic(conn->engine);

    return stream->stream_send_offset;
}

ssize_t
xqc_stream_write_buff(xqc_stream_t *stream,
                      unsigned char *send_data,
                      size_t send_data_size,
                      uint8_t fin)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_stream_write_buff_list_t *buff_list = &stream->stream_write_buff_list;
    xqc_stream_write_buff_t *write_buff = xqc_calloc(1, sizeof(xqc_stream_write_buff_t));
    if (!write_buff) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    write_buff->sw_data = xqc_malloc(send_data_size);
    memcpy(write_buff->sw_data, send_data, send_data_size);
    write_buff->data_length = send_data_size;
    write_buff->data_offset += buff_list->total_len;
    write_buff->next_write_offset = 0;
    write_buff->fin = fin;

    buff_list->total_len += send_data_size;
    xqc_list_add_tail(&write_buff->sw_list, &buff_list->write_buff_list);

    return send_data_size;
}

int
xqc_stream_write_buff_to_packets(xqc_stream_t *stream)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    xqc_stream_write_buff_list_t *buff_list = &stream->stream_write_buff_list;
    xqc_stream_write_buff_t *write_buff;
    xqc_list_head_t *pos, *next;
    unsigned char *send_data;
    size_t send_data_size;
    size_t offset;
    size_t send_data_written;
    int ret;
    unsigned char fin;

    xqc_list_for_each_safe(pos, next, &buff_list->write_buff_list) {
        write_buff = xqc_list_entry(pos, xqc_stream_write_buff_t, sw_list);
        send_data_size = write_buff->data_length;
        offset = 0;
        fin = write_buff->fin;
        send_data = write_buff->sw_data;
        uint8_t fin_only = fin && send_data_size == 0;

        while (offset < send_data_size || fin_only) {

            ret = xqc_write_stream_frame_to_packet(conn, stream, pkt_type,
                                             fin,
                                             send_data + offset,
                                             send_data_size - offset,
                                             &send_data_written);
            if (ret) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stream_frame_to_packet error|");
                return ret;
            }
            offset += send_data_written;
            if (fin_only) {
                break;
            }
        }

        xqc_list_del_init(&write_buff->sw_list);
        xqc_destroy_write_buff(write_buff);
    }
    return XQC_OK;
}

void
xqc_process_write_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_write_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, write_stream_list);
        if (stream->stream_flag & XQC_SF_STREAM_DATA_BLOCKED
            || conn->conn_flag & XQC_CONN_FLAG_DATA_BLOCKED) {
            continue;
        }
        ret = stream->stream_if->stream_write_notify(stream, stream->user_data);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_write_notify|flag=%d", stream->stream_flag);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify err|%d|", ret);
            xqc_stream_shutdown_write(stream);
        }
    }
}

void
xqc_process_read_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_read_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, read_stream_list);
        ret = stream->stream_if->stream_read_notify(stream, stream->user_data);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_read_notify|flag=%d", stream->stream_flag);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify err|%d|", ret);
            xqc_stream_shutdown_read(stream);
        }
    }
}

void
xqc_process_crypto_write_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    for (int i = XQC_ENC_LEV_INIT; i < XQC_ENC_MAX_LEVEL; i++) {
        stream = conn->crypto_stream[i];
        if (stream && (stream->stream_flag & XQC_SF_READY_TO_WRITE)) {
            ret = stream->stream_if->stream_write_notify(stream, stream->user_data);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify crypto err|%d|", ret);
                xqc_stream_shutdown_write(stream);
            }
        }
    }
}

void
xqc_process_crypto_read_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    for (int i = XQC_ENC_LEV_INIT; i < XQC_ENC_MAX_LEVEL; i++) {
        stream = conn->crypto_stream[i];
        if (stream && (stream->stream_flag & XQC_SF_READY_TO_READ)) {
            ret = stream->stream_if->stream_read_notify(stream, stream->user_data);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify crypto err|%d|", ret);
                xqc_stream_shutdown_read(stream);
            }
        }
    }
}

void
xqc_destroy_stream_frame(xqc_stream_frame_t *stream_frame)
{
    xqc_free(stream_frame->data);
    xqc_free(stream_frame);
}

void
xqc_destroy_write_buff(xqc_stream_write_buff_t *write_buff)
{
    xqc_free(write_buff->sw_data);
    xqc_free(write_buff);
}

void
xqc_destroy_frame_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_frame_t *stream_frame;
    xqc_list_for_each_safe(pos, next, head) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        xqc_list_del_init(pos);
        xqc_destroy_stream_frame(stream_frame);
    }
}

void
xqc_destroy_write_buff_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_write_buff_t *write_buff;
    xqc_list_for_each_safe(pos, next, head) {
        write_buff = xqc_list_entry(pos, xqc_stream_write_buff_t, sw_list);
        xqc_list_del_init(pos);
        xqc_destroy_write_buff(write_buff);
    }
}
