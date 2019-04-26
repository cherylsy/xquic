#include "xqc_conn.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_transport.h"
#include "xqc_packet_out.h"
#include "xqc_send_ctl.h"
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"

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
        xqc_list_add_tail(&stream->write_stream_list, &stream->stream_conn->conn_write_streams);
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
        xqc_list_del_init(&stream->write_stream_list);
        stream->stream_flag &= ~XQC_SF_READY_TO_WRITE;
    }
}

void
xqc_stream_ready_to_read (xqc_stream_t *stream)
{
    if (!(stream->stream_flag & XQC_SF_READY_TO_READ)) {
        xqc_list_add_tail(&stream->read_stream_list, &stream->stream_conn->conn_read_streams);
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
        xqc_list_del_init(&stream->read_stream_list);
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
    stream->stream_flow_ctl.fc_max_stream_data_bidi_local = trans_param->initial_max_stream_data_bidi_local;
    stream->stream_flow_ctl.fc_max_stream_data_bidi_remote = trans_param->initial_max_stream_data_bidi_remote;
    stream->stream_flow_ctl.fc_max_stream_data_uni = trans_param->initial_max_stream_data_uni;
}

xqc_stream_t *
xqc_create_stream (xqc_connection_t *conn,
                  void *user_data)
{
    if (conn->cur_stream_id_bidi_local >= conn->conn_flow_ctl.fc_max_streams_bidi) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_stream|exceed max_streams_bidi|%d|",
                conn->conn_flow_ctl.fc_max_streams_bidi);//TODO: send STREAMS_BLOCKED Frame
        return NULL;
    }

    xqc_stream_t *stream = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    stream->stream_id_type = XQC_CLI_BID;
    stream->stream_id = xqc_gen_stream_id(conn, stream->stream_id_type);
    stream->stream_conn = conn;
    stream->stream_if = &conn->engine->eng_callback.stream_callbacks;
    stream->user_data = user_data;

    xqc_stream_set_flow_ctl(stream, &conn->trans_param);

    xqc_id_hash_element_t e = {stream->stream_id, stream};
    if (xqc_id_hash_add(conn->streams_hash, e)) {
        return NULL;
    }

    xqc_init_list_head(&stream->stream_data_in.frames_tailq);

    xqc_stream_ready_to_write(stream);

    return stream;
}

int xqc_crypto_stream_on_read (xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_pkt_type_t pkt_type;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    xqc_conn_state_t next_state;
    switch (cur_state) {
        case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
            next_state = XQC_CONN_STATE_CLIENT_INITIAL_RECVD;
            break;
        case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
            next_state = XQC_CONN_STATE_ESTABED;
            break;
        case XQC_CONN_STATE_SERVER_INIT:
            next_state = XQC_CONN_STATE_SERVER_INITIAL_RECVD;
            break;
        case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
            next_state = XQC_CONN_STATE_ESTABED;
            break;
        default:
            return -1;
    }

    if (next_state == XQC_CONN_STATE_CLIENT_INITIAL_RECVD &&
        stream->stream_conn->crypto_stream[XQC_ENC_LEV_HSK] == NULL) {
        stream->stream_conn->crypto_stream[XQC_ENC_LEV_HSK] = xqc_create_crypto_stream(stream->stream_conn, NULL);
    }
    stream->stream_conn->conn_state = next_state;

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "xqc_crypto_stream_on_read cur_state=%d, next_state=%d",
            cur_state, next_state);
    return 0;
}

int xqc_crypto_stream_on_write (xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    char send_data[100] = {0};
    unsigned send_data_size = 100;//TODO: 假数据

    xqc_pkt_num_space_t pns;
    xqc_pkt_type_t pkt_type;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    if (cur_state == XQC_CONN_STATE_CLIENT_INIT ||
        cur_state == XQC_CONN_STATE_SERVER_INITIAL_RECVD) {
        pns = XQC_PNS_INIT;
        pkt_type = XQC_PTYPE_INIT;
    } else if (cur_state == XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD ||
               cur_state == XQC_CONN_STATE_SERVER_INITIAL_SENT ||
               cur_state == XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD) {
        pns = XQC_PNS_HSK;
        pkt_type = XQC_PTYPE_HSK;
    } else {
        return -1;
    }

    size_t send_data_written = 0;
    size_t offset = 0;
    int n_written = 0;
    xqc_packet_out_t *packet_out;
    xqc_connection_t *c = stream->stream_conn;

    while (stream->stream_send_offset < send_data_size) {
        unsigned int header_size = xqc_crypto_frame_header_size(stream->stream_send_offset,
                                                                send_data_size - offset);
        packet_out = xqc_send_ctl_get_packet_out(c->conn_send_ctl, header_size + 1, pns);
        if (packet_out == NULL) {
            return -1;
        }

        //TODO calc packet_number_bits
        unsigned char packet_number_bits = 0;

        //check if header is created
        if (!packet_out->po_used_size) {
            n_written = xqc_gen_long_packet_header(packet_out,
                                                    c->dcid.cid_buf, c->dcid.cid_len,
                                                    c->scid.cid_buf, c->scid.cid_len,
                                                    NULL, 0,
                                                    c->version, pkt_type,
                                                    packet_out->po_pkt.pkt_num, packet_number_bits);
            if (n_written < 0) {
                return -1;
            }
            packet_out->po_used_size += n_written;
        }

        n_written = xqc_gen_crypto_frame(packet_out->po_buf + packet_out->po_used_size,
                                         packet_out->po_buf_size - packet_out->po_used_size,
                                         stream->stream_send_offset,
                                         send_data + offset,
                                         send_data_size - offset,
                                         &send_data_written);
        if (n_written < 0) {
            return -1;
        }
        offset += send_data_written;
        stream->stream_send_offset += send_data_written;
        packet_out->po_used_size += n_written;

        packet_out->po_frame_types |= XQC_FRAME_BIT_CRYPTO;

        xqc_long_packet_update_length(packet_out);
    }

    xqc_stream_shutdown_write(stream);

    xqc_conn_state_t next_state;
    switch (stream->stream_conn->conn_state) {
        case XQC_CONN_STATE_CLIENT_INIT:
            next_state = XQC_CONN_STATE_CLIENT_INITIAL_SENT;
            break;
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
            next_state = XQC_CONN_STATE_SERVER_INITIAL_SENT;
            break;
        case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
            next_state = XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT;
            break;
        case XQC_CONN_STATE_SERVER_INITIAL_SENT:
            next_state = XQC_CONN_STATE_SERVER_HANDSHAKE_SENT;
            break;
        case XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD:
            next_state = XQC_CONN_STATE_ESTABED;
            break;
        default:
            return -1;
    }
    stream->stream_conn->conn_state = next_state;

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "xqc_crypto_stream_on_write cur_state=%d, next_state=%d",
        cur_state, next_state);
    return 0;
}

xqc_stream_callbacks_t crypto_stream_callback = {
        .stream_read_notify = xqc_crypto_stream_on_read,
        .stream_write_notify = xqc_crypto_stream_on_write,
};

xqc_stream_t *
xqc_create_crypto_stream (xqc_connection_t *conn,
                          void *user_data)
{
    xqc_stream_t *stream = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    stream->stream_id_type = XQC_CLI_BID;
    stream->stream_conn = conn;
    stream->stream_if = &crypto_stream_callback;
    stream->user_data = user_data;

    xqc_stream_ready_to_write(stream);

    return stream;
}

ssize_t
xqc_stream_send (xqc_stream_t *stream,
                 unsigned char *send_data,
                 size_t send_data_size,
                 uint8_t fin)
{
    size_t send_data_written = 0;
    size_t offset = 0; //本次send_data中的已写offset
    int n_written = 0;
    xqc_connection_t *c = stream->stream_conn;
    xqc_packet_out_t *packet_out;
    uint8_t fin_only = fin && !send_data_size;

    while (offset < send_data_size || fin_only) {
        if (stream->stream_conn->conn_flow_ctl.fc_data_sent >= stream->stream_conn->conn_flow_ctl.fc_max_data) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_stream_send|exceed max_data|%d|",
                    stream->stream_conn->conn_flow_ctl.fc_max_data);//TODO: send DATA_BLOCKED Frame
            break;
        }
        if (stream->stream_send_offset >= stream->stream_flow_ctl.fc_max_stream_data_bidi_remote) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_stream_send|exceed max_stream_data_bidi_remote|%d|",
                    stream->stream_flow_ctl.fc_max_stream_data_bidi_remote);//TODO: send STREAMS_DATA_BLOCKED Frame
            break;
        }

        unsigned int header_size = xqc_stream_frame_header_size(stream->stream_id,
                                                                stream->stream_send_offset,
                                                                send_data_size - offset);
        packet_out = xqc_send_ctl_get_packet_out(c->conn_send_ctl, header_size + 1, XQC_PNS_01RTT);
        if (packet_out == NULL) {
            return -1;
        }

        //TODO calc packet_number_bits
        unsigned char packet_number_bits = 0;

        //check if header is created
        if (!packet_out->po_used_size) {
            n_written = xqc_gen_short_packet_header(packet_out->po_buf,
                                                    packet_out->po_buf_size - packet_out->po_used_size,
                                                    c->dcid.cid_buf, c->dcid.cid_len,
                                                    packet_number_bits, packet_out->po_pkt.pkt_num);
            if (n_written < 0) {
                return -1;
            }
            packet_out->po_used_size += n_written;
        }

        n_written = xqc_gen_stream_frame(packet_out->po_buf + packet_out->po_used_size,
                                         packet_out->po_buf_size - packet_out->po_used_size,
                                         stream->stream_id, stream->stream_send_offset, fin,
                                         send_data + offset,
                                         send_data_size - offset,
                                         &send_data_written);
        if (n_written < 0) {
            return -1;
        }
        offset += send_data_written;
        stream->stream_send_offset += send_data_written;
        stream->stream_conn->conn_flow_ctl.fc_data_sent += send_data_written;
        packet_out->po_used_size += n_written;

        packet_out->po_frame_types |= XQC_FRAME_BIT_STREAM;

        fin_only = 0;
    }


    xqc_stream_shutdown_write(stream);

    return stream->stream_send_offset;
}

void
xqc_process_write_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos;

    xqc_list_for_each(pos, &conn->conn_write_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, write_stream_list);
        ret = stream->stream_if->stream_write_notify(stream, stream->user_data);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify err|%d|", ret);
        }
    }
}

void
xqc_process_read_streams (xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos;

    xqc_list_for_each(pos, &conn->conn_read_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, read_stream_list);
        ret = stream->stream_if->stream_read_notify(stream, stream->user_data);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify err|%d|", ret);
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
            }
        }
    }
}
