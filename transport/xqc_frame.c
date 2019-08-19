
#include <common/xqc_log.h>
#include <common/xqc_errno.h>
#include "xqc_frame.h"
#include "include/xquic_typedef.h"
#include "common/xqc_variable_len_int.h"
#include "xqc_transport.h"
#include "common/xqc_log.h"
#include "xqc_packet_in.h"
#include "xqc_conn.h"
#include "xqc_frame_parser.h"
#include "xqc_send_ctl.h"
#include "xqc_stream.h"
#include "crypto/xqc_tls_public.h"


static const char * const frame_type_2_str[XQC_FRAME_NUM] = {
    [XQC_FRAME_PADDING]             = "PADDING",
    [XQC_FRAME_PING]                = "PING",
    [XQC_FRAME_ACK]                 = "ACK",
    [XQC_FRAME_RESET_STREAM]        = "RESET_STREAM",
    [XQC_FRAME_STOP_SENDING]        = "STOP_SENDING",
    [XQC_FRAME_CRYPTO]              = "CRYPTO",
    [XQC_FRAME_NEW_TOKEN]           = "NEW_TOKEN",
    [XQC_FRAME_STREAM]              = "STREAM",
    [XQC_FRAME_MAX_DATA]            = "MAX_DATA",
    [XQC_FRAME_MAX_STREAM_DATA]     = "MAX_STREAM_DAT",
    [XQC_FRAME_MAX_STREAMS]         = "MAX_STREAMS",
    [XQC_FRAME_DATA_BLOCKED]        = "DATA_BLOCKED",
    [XQC_FRAME_STREAM_DATA_BLOCKED] = "STREAM_DATA_BLOCKED",
    [XQC_FRAME_STREAMS_BLOCKED]     = "STREAMS_BLOCKED",
    [XQC_FRAME_NEW_CONNECTION_ID]   = "NEW_CONNECTION_ID",
    [XQC_FRAME_RETIRE_CONNECTION_ID]= "RETIRE_CONNECTION_ID",
    [XQC_FRAME_PATH_CHALLENGE]      = "PATH_CHALLENGE",
    [XQC_FRAME_PATH_RESPONSE]       = "PATH_RESPONSE",
    [XQC_FRAME_CONNECTION_CLOSE]    = "CONNECTION_CLOSE",
    [XQC_FRAME_Extension]           = "Extension",
};

static char g_frame_type_buf[128];

const char*
xqc_frame_type_2_str (xqc_frame_type_bit_t type_bit)
{
    g_frame_type_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_FRAME_NUM; i++) {
        if (type_bit & 1 << i) {
            wsize = snprintf(g_frame_type_buf + pos, sizeof(g_frame_type_buf) - pos, "%s ", frame_type_2_str[i]);
            pos += wsize;
        }
    }
    return g_frame_type_buf;
}

unsigned int
xqc_stream_frame_header_size (xqc_stream_id_t stream_id, uint64_t offset, size_t length)
{
    return 1 + xqc_vint_len_by_val(stream_id) +
            offset ? xqc_vint_len_by_val(offset) : 0 +
            xqc_vint_len_by_val(length);

}

unsigned int
xqc_crypto_frame_header_size (uint64_t offset, size_t length)
{
    return 1 +
           xqc_vint_len_by_val(offset) +
           xqc_vint_len_by_val(length);

}

xqc_int_t
xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *new_frame)
{

    //insert xqc_stream_frame_t into stream->stream_data_in.frames_tailq in order of offset
    unsigned char inserted = 0;
    xqc_list_head_t *pos;
    xqc_stream_frame_t *frame;
    xqc_list_for_each_reverse(pos, &stream->stream_data_in.frames_tailq) {
        frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (xqc_max(frame->data_offset, new_frame->data_offset) <
                xqc_min(frame->data_offset + frame->data_length, new_frame->data_offset + new_frame->data_length)) {
            /*
             * overlap
             *      |-----------|   frame
             * |-----------|        new_frame
             *        |------------|new_frame
             *        |----|        new_frame  do not insert
             * |-------------------|new_frame
             */
            xqc_log(conn->log, XQC_LOG_WARN, "|is overlap|");
        }
        if (new_frame->data_offset >= frame->data_offset &&
            new_frame->data_offset + new_frame->data_length <= frame->data_offset + frame->data_length) {
            xqc_log(conn->log, XQC_LOG_WARN, "|already recvd|");
            xqc_free(new_frame->data);
            xqc_free(new_frame);
            return XQC_OK;
        }

        if (new_frame->data_offset >= frame->data_offset) {
            xqc_list_add(&new_frame->sf_list, pos);
            inserted = 1;
            break;
        }
    }
    if (!inserted) {
        xqc_list_add(&new_frame->sf_list, &stream->stream_data_in.frames_tailq);
    }

    /*
     * can merge
     * |--------------|merged_offset_end
     *          |----------|
     *                |--------|
     */
    //merge
    if (stream->stream_data_in.merged_offset_end >= new_frame->data_offset &&
        stream->stream_data_in.merged_offset_end < new_frame->data_offset + new_frame->data_length) {

        stream->stream_data_in.merged_offset_end = new_frame->data_offset + new_frame->data_length;
        xqc_list_for_each(pos, &new_frame->sf_list) {
            frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
            if (stream->stream_data_in.merged_offset_end >= frame->data_offset &&
                stream->stream_data_in.merged_offset_end < frame->data_offset + frame->data_length) {
                stream->stream_data_in.merged_offset_end = frame->data_offset + frame->data_length;
            }
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned char *last_pos = NULL;

    while (packet_in->pos < packet_in->last) {
        last_pos = packet_in->pos;

        if (conn->conn_state == XQC_CONN_STATE_CLOSING) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|closing state|frame_type:0x%xd|",
                    packet_in->pos[0]);
            /* respond connection close when recv any packet */
            if (packet_in->pos[0] != 0x1c && packet_in->pos[0] != 0x1d) {
                xqc_conn_immediate_close(conn);
                packet_in->pos = packet_in->last;
                return XQC_OK;
            }
        } else if (conn->conn_state == XQC_CONN_STATE_DRAINING) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|draining state, skip|");
            /* do not respond any packet */
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        xqc_log(conn->log, XQC_LOG_DEBUG, "|frame_type:0x%xd|",
                packet_in->pos[0]);

        switch (packet_in->pos[0]) {
            case 0x00:
                //padding frame
                ret = xqc_process_padding_frame(conn, packet_in);
                break;
            case 0x02 ... 0x03:
                //ack frame
                ret = xqc_process_ack_frame(conn, packet_in);
                break;
            case 0x04:
                ret = xqc_process_reset_stream_frame(conn, packet_in);
                break;
            case 0x05:
                ret = xqc_process_stop_sending_frame(conn, packet_in);
                break;
            case 0x06:
                //crypto frame
                ret = xqc_process_crypto_frame(conn, packet_in);
                break;
            case 0x07:
                ret = xqc_process_new_token_frame(conn, packet_in);
                break;
            case 0x08 ... 0x0f:
                //stream frame
                ret = xqc_process_stream_frame(conn, packet_in);
                break;
            case 0x10:
                ret = xqc_process_max_data_frame(conn, packet_in);
                break;
            case 0x11:
                ret = xqc_process_max_stream_data_frame(conn, packet_in);
                break;
            case 0x12 ... 0x13:
                ret = xqc_process_max_streams_frame(conn, packet_in);
                break;
            case 0x14:
                ret = xqc_process_data_blocked_frame(conn, packet_in);
                break;
            case 0x15:
                ret = xqc_process_stream_data_blocked_frame(conn, packet_in);
                break;
            case 0x16 ... 0x17:
                ret = xqc_process_streams_blocked_frame(conn, packet_in);
                break;
            case 0x1c ... 0x1d:
                ret = xqc_process_conn_close_frame(conn, packet_in);
                break;
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|unknown frame type|");
                return -XQC_EILLPKT;
        }

        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|process frame error|");
            return ret;
        }

        if (last_pos == packet_in->pos) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|pos not update|");
            return -XQC_ESYS;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|process padding|");
    ret = xqc_parse_padding_frame(packet_in, conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_padding_frame error|");
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = 0;

    xqc_stream_id_t stream_id;
    xqc_stream_t *stream = NULL;
    xqc_stream_frame_t *stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    if (stream_frame == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    ret = xqc_parse_stream_frame(packet_in, conn, stream_frame, &stream_id);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_stream_frame error|ret:%d|", ret);
        goto error;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|offset:%ui|data_length:%ui|fin:%ud|",
            stream_frame->data_offset, stream_frame->data_length, stream_frame->fin);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|cannot find stream|");
        ret = -XQC_ENULLPTR;
        goto error;
    }

    if (stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD) {
        ret = XQC_OK;
        goto free;
    }

    if (stream_frame->fin) {
        if (stream->stream_data_in.stream_length > 0
                && stream->stream_data_in.stream_length != stream_frame->data_offset + stream_frame->data_length) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|final size changed|");
            XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
            ret = -XQC_EPROTO;
            goto error;
        }

        stream->stream_data_in.stream_length = stream_frame->data_offset + stream_frame->data_length;
        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV) {
            stream->stream_state_recv = XQC_RECV_STREAM_ST_SIZE_KNOWN;
        }
    }
    if (stream->stream_data_in.stream_length > 0
            && stream_frame->data_offset + stream_frame->data_length > stream->stream_data_in.stream_length) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|exceed final size|");
        XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
        ret = -XQC_EPROTO;
        goto error;
    }

    if (stream_frame->data_offset + stream_frame->data_length <= stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|already read|data_offset:%ui|data_length:%ui|merged_offset_end:%ui|",
                stream_frame->data_offset, stream_frame->data_length, stream->stream_data_in.merged_offset_end);
        goto free;
    }

    ret = xqc_insert_stream_frame(conn, stream, stream_frame);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_insert_stream_frame error|");
        goto error;
    }
    if (stream->stream_data_in.stream_length == stream->stream_data_in.merged_offset_end) {
        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN) {
            stream->stream_state_recv = XQC_RECV_STREAM_ST_DATA_RECVD;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_stream_ready_to_read all recvd|");
        xqc_stream_ready_to_read(stream);
    }
    else if (stream->stream_data_in.next_read_offset < stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_stream_ready_to_read part recvd|");
        xqc_stream_ready_to_read(stream);
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_length:%ui|merged_offset_end:%ui|",
            stream->stream_data_in.stream_length, stream->stream_data_in.merged_offset_end);

    return XQC_OK;

error:
free:
    xqc_free(stream_frame->data);
    xqc_free(stream_frame);
    return ret;
}


xqc_int_t xqc_insert_crypto_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *stream_frame){

    unsigned char inserted = 0;
    xqc_list_head_t *pos;
    xqc_stream_frame_t *frame;
    xqc_list_for_each_reverse(pos, &stream->stream_data_in.frames_tailq) {
        frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (stream_frame->data_offset >= frame->data_offset ) {
            xqc_list_add(&stream_frame->sf_list, pos);
            inserted = 1;
            break;
        }
    }
    if (!inserted) {
        xqc_list_add(&stream_frame->sf_list, &stream->stream_data_in.frames_tailq);
    }

    return XQC_OK;

}


xqc_int_t
xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    /*  check token
     *  initial+ack时不校验token，因此在解crypto时校验
     * */
    if (!(conn->conn_flag & XQC_CONN_FLAG_TOKEN_OK)
            && conn->conn_type == XQC_CONN_TYPE_SERVER
            && packet_in->pi_pkt.pkt_type == XQC_PTYPE_INIT) {

        if (xqc_conn_check_token(conn, conn->conn_token, conn->conn_token_len)) {
            conn->conn_flag |= XQC_CONN_FLAG_TOKEN_OK;
        } else {
            unsigned char token[XQC_MAX_TOKEN_LEN];
            unsigned token_len = XQC_MAX_TOKEN_LEN;
            xqc_conn_gen_token(conn, token, &token_len);
            if (xqc_conn_send_retry(conn, token, token_len) != 0) {
                return -XQC_ESEND_RETRY;
            }
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }
    }

#if 0
    if (conn->conn_state >= XQC_CONN_STATE_ESTABED) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_process_crypto_frame|recvd crypto after conn estabed|");
        packet_in->pos = packet_in->last;
        packet_in->pi_frame_types |= XQC_FRAME_BIT_CRYPTO;
        return XQC_OK;
    }
#endif

    xqc_stream_frame_t *stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    ret = xqc_parse_crypto_frame(packet_in, conn, stream_frame);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_crypto_frame error|");
        return ret;
    }

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_in->pi_pkt.pkt_type);
    if(conn->crypto_stream[encrypt_level] == NULL){
        conn->crypto_stream[encrypt_level] = xqc_create_crypto_stream(conn, encrypt_level, NULL);
        if (conn->crypto_stream[encrypt_level] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_crypto_stream error|");
            return -XQC_ENULLPTR;
        }
    }

    xqc_stream_t *stream = conn->crypto_stream[encrypt_level];

    ret = xqc_insert_crypto_frame(conn, stream, stream_frame);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_insert_crypto_frame error|");
        return -1;
    }

    ret = xqc_read_crypto_stream(stream);
    if(ret < 0){
        return ret;
    }
    xqc_stream_ready_to_read(stream);


    if (conn->conn_type == XQC_CONN_TYPE_SERVER &&
        encrypt_level == XQC_ENC_LEV_INIT && conn->crypto_stream[XQC_ENC_LEV_HSK] == NULL) {
        conn->crypto_stream[XQC_ENC_LEV_HSK] = xqc_create_crypto_stream(conn, XQC_ENC_LEV_HSK, NULL);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|server create hsk stream|");
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER &&
        encrypt_level == XQC_ENC_LEV_HSK && conn->crypto_stream[XQC_ENC_LEV_1RTT] == NULL) {
        conn->crypto_stream[XQC_ENC_LEV_1RTT] = xqc_create_crypto_stream(conn, XQC_ENC_LEV_1RTT, NULL);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|server create 1RTT stream|");
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_ack_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    xqc_ack_info_t ack_info;
    ret = xqc_parse_ack_frame(packet_in, conn, &ack_info);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_ack_frame error|");
        return ret;
    }

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|high:%ui|low:%ui|pkt_pns:%d|",
        ack_info.ranges[i].high, ack_info.ranges[i].low, packet_in->pi_pkt.pkt_pns);
    }

    ret = xqc_send_ctl_on_ack_received(conn->conn_send_ctl, &ack_info, packet_in->pkt_recv_time);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_on_ack_received error|");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_conn_close_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned short err_code;

    ret = xqc_parse_conn_close_frame(packet_in, &err_code);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_conn_close_frame error|");
        return ret;
    }

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        ret = xqc_conn_immediate_close(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|xqc_conn_immediate_close error|");
            return ret;
        }
    }
    conn->conn_state = XQC_CONN_STATE_DRAINING;

    return XQC_OK;
}

xqc_int_t
xqc_process_reset_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned short err_code;
    xqc_stream_id_t stream_id;
    uint64_t final_size;
    xqc_stream_t *stream;

    ret = xqc_parse_reset_stream_frame(packet_in, &stream_id, &err_code, &final_size);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_reset_stream_frame error|");
        return ret;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|cannot find stream|");
        return -XQC_ENULLPTR;
    }

    if (stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD) {
        stream->stream_state_recv = XQC_RECV_STREAM_ST_RESET_RECVD;

        xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq);
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_stop_sending_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned short err_code;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_stop_sending_frame(packet_in, &stream_id, &err_code);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_stop_sending_frame error|");
        return ret;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|cannot find stream|");
        XQC_CONN_ERR(conn, TRA_STREAM_STATE_ERROR);
        return -XQC_ENULLPTR;
    }

    /*
     * An endpoint that receives a STOP_SENDING frame
   MUST send a RESET_STREAM frame if the stream is in the Ready or Send
   state.
     */

    return XQC_OK;
}

xqc_int_t
xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t data_limit;

    ret = xqc_parse_data_blocked_frame(packet_in, &data_limit);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_data_blocked_frame error|");
        return ret;
    }

    ret = xqc_write_max_data_to_packet(conn, data_limit * 2);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_write_max_data_to_packet error|");
        return ret;
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_stream_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t stream_data_limit;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_stream_data_blocked_frame(packet_in, &stream_id, &stream_data_limit);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_stream_data_blocked_frame error|");
        return ret;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|cannot find stream|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_write_max_stream_data_to_packet(conn, stream_id, stream_data_limit * 2);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_write_max_stream_data_to_packet error|");
        return ret;
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_streams_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t stream_limit;
    int bidirectional;

    ret = xqc_parse_streams_blocked_frame(packet_in, &stream_limit, &bidirectional);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_streams_blocked_frame error|");
        return ret;
    }

    ret = xqc_write_max_streams_to_packet(conn, stream_limit * 2, bidirectional);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_write_max_streams_to_packet error|");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_max_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t max_data;

    ret = xqc_parse_max_data_frame(packet_in, &max_data);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_max_data_frame error|");
        return ret;
    }

    if (max_data > conn->conn_flow_ctl.fc_max_data) {
        conn->conn_flow_ctl.fc_max_data = max_data;
        conn->conn_flag &= ~XQC_CONN_FLAG_DATA_BLOCKED;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|max_data:%ui|", max_data);
    } else {
        xqc_log(conn->log, XQC_LOG_WARN, "|max_data too small|");
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_max_stream_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t max_stream_data;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_max_stream_data_frame(packet_in, &stream_id, &max_stream_data);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_max_stream_data_frame error|");
        return ret;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|cannot find stream|");
        XQC_CONN_ERR(conn, TRA_STREAM_STATE_ERROR);
        return -XQC_ENULLPTR;
    }
    if (max_stream_data > stream->stream_flow_ctl.fc_max_stream_data) {
        stream->stream_flow_ctl.fc_max_stream_data = max_stream_data;
        stream->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
        xqc_log(conn->log, XQC_LOG_WARN,
                "|max_stream_data=%ui|", max_stream_data);
    } else {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|max_stream_data too small|");
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_max_streams_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t max_streams;
    int bidirectional;

    ret = xqc_parse_max_streams_frame(packet_in, &max_streams, &bidirectional);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_max_streams_frame error|");
        return ret;
    }

    if (bidirectional) {
        conn->conn_flow_ctl.fc_max_streams_bidi = max_streams;
    } else {
        conn->conn_flow_ctl.fc_max_streams_uni = max_streams;
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_new_token_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;

    conn->conn_token_len = XQC_MAX_TOKEN_LEN;
    ret = xqc_parse_new_token_frame(packet_in, conn->conn_token, &conn->conn_token_len);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_new_token_frame error|");
        return ret;
    }

    conn->engine->eng_callback.save_token(conn->conn_token, conn->conn_token_len);

    return XQC_OK;
}
