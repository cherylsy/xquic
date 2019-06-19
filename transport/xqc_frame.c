
#include <common/xqc_log.h>
#include <common/xqc_errno.h>
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_transport.h"
#include "common/xqc_log.h"
#include "xqc_packet_in.h"
#include "xqc_conn.h"
#include "xqc_frame_parser.h"
#include "xqc_send_ctl.h"
#include "xqc_stream.h"


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
xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *stream_frame)
{

    //insert xqc_stream_frame_t into stream->stream_data_in.frames_tailq in order of offset
    unsigned char inserted = 0;
    xqc_list_head_t *pos;
    xqc_stream_frame_t *frame;
    xqc_list_for_each_reverse(pos, &stream->stream_data_in.frames_tailq) {
        frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (stream_frame->data_offset >= frame->data_offset + frame->data_length) {
            xqc_list_add(&stream_frame->sf_list, pos);
            inserted = 1;
            break;
        }
    }
    if (!inserted) {
        xqc_list_add(&stream_frame->sf_list, &stream->stream_data_in.frames_tailq);
    }

    //merge
    if (stream->stream_data_in.merged_offset_end == stream_frame->data_offset) {
        stream->stream_data_in.merged_offset_end = stream_frame->data_offset + stream_frame->data_length;
        xqc_list_for_each(pos, &stream_frame->sf_list) {
            frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
            if (stream->stream_data_in.merged_offset_end == frame->data_offset) {
                stream->stream_data_in.merged_offset_end = frame->data_offset + frame->data_length;
            } else if (stream->stream_data_in.merged_offset_end < frame->data_offset) {
                break;
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
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_frames|closing state|frame_type=0x%xd|", packet_in->pos[0]);
            /* respond connection close when recv any packet */
            if (packet_in->pos[0] != 0x1c && packet_in->pos[0] != 0x1d) {
                xqc_conn_immediate_close(conn);
                packet_in->pos = packet_in->last;
                return XQC_OK;
            }
        } else if (conn->conn_state == XQC_CONN_STATE_DRAINING) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_frames|draining state, skip|");
            /* do not respond any packet */
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        switch (packet_in->pos[0]) {
            case 0x00:
                //padding frame
                ret = xqc_process_padding_frame(conn, packet_in);
                break;
            case 0x02 ... 0x03:
                //ack frame
                ret = xqc_process_ack_frame(conn, packet_in);
                break;
            case 0x06:
                //crypto frame
                ret = xqc_process_crypto_frame(conn, packet_in);
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
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|unknown frame type|");
                return -XQC_EILLPKT;
        }

        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|process frame error|");
            return ret;
        }

        if (last_pos == packet_in->pos) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|pos not update|");
            return -XQC_ESYS;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    ret = xqc_parse_padding_frame(packet_in, conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_padding_frame|xqc_parse_padding_frame error|");
        return ret;
    }

    return XQC_OK;
}

void
xqc_destroy_stream_frame(xqc_stream_frame_t *stream_frame)
{
    xqc_free(stream_frame->data);
    xqc_free(stream_frame);
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

xqc_int_t
xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = 0;

    xqc_stream_id_t stream_id;
    xqc_stream_t *stream = NULL;
    xqc_stream_frame_t *stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    if (stream_frame == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_frame|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    ret = xqc_parse_stream_frame(packet_in, conn, stream_frame, &stream_id);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_frame|xqc_parse_stream_frame error|");
        goto error;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream && conn->conn_type == XQC_CONN_TYPE_SERVER) {
        stream = xqc_server_create_stream(conn, stream_id, NULL);
    }

    if (!stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_frame|cannot find stream|");
        ret = -XQC_ENULLPTR;
        goto error;
    }

    if (stream_frame->fin) {
        stream->stream_data_in.stream_length = stream_frame->data_offset + stream_frame->data_length;
    }

    if (stream_frame->data_offset + stream_frame->data_length <= stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|already read|data_offset: %ui, data_length: %u, merged_offset_end: %ui",
                stream_frame->data_offset, stream_frame->data_length, stream->stream_data_in.merged_offset_end);
        goto free;
    }
    else if (stream_frame->data_offset < stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_WARN, "|error offset|data_offset: %ui, data_length: %u, merged_offset_end: %ui",
                stream_frame->data_offset, stream_frame->data_length, stream->stream_data_in.merged_offset_end);
        ret = -XQC_EOFFSET;
        goto error;
    }

    ret = xqc_insert_stream_frame(conn, stream, stream_frame);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_frame|xqc_insert_stream_frame|");
        goto error;
    }
    if (stream->stream_data_in.stream_length == stream->stream_data_in.merged_offset_end) {
    //if (stream->stream_data_in.next_read_offset < stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_stream_frame|xqc_stream_ready_to_read|");
        xqc_stream_ready_to_read(stream);
    }

    return XQC_OK;

error:
free:
    xqc_free(stream_frame->data);
    xqc_free(stream_frame);
    return ret;
}

xqc_int_t
xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    if (xqc_conn_check_handshake_completed(conn)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_crypto_frame|recvd long header packet after handshake finishd|");
        packet_in->pos = packet_in->last;
        return XQC_OK;
    }

    ret = xqc_parse_crypto_frame(packet_in, conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_crypto_frame|xqc_parse_crypto_frame error|");
        return ret;
    }

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_in->pi_pkt.pkt_type);
    xqc_stream_t *stream = conn->crypto_stream[encrypt_level];
    if (stream) {
        xqc_stream_ready_to_read(stream);
    } else {
        conn->crypto_stream[encrypt_level] = xqc_create_crypto_stream(conn, encrypt_level, NULL);
        if (conn->crypto_stream[encrypt_level] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_crypto_frame|xqc_create_crypto_stream err|");
            return -XQC_ENULLPTR;
        }
        xqc_stream_ready_to_read(conn->crypto_stream[encrypt_level]);
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER &&
        encrypt_level == XQC_ENC_LEV_INIT && conn->crypto_stream[XQC_ENC_LEV_HSK] == NULL) {
        conn->crypto_stream[XQC_ENC_LEV_HSK] = xqc_create_crypto_stream(conn, XQC_ENC_LEV_HSK, NULL);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_crypto_frame|server create hsk stream|");
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_ack_frame|xqc_parse_ack_frame error|");
        return ret;
    }

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_ack_frame|high: %ui, low: %ui|",
        ack_info.ranges[i].high, ack_info.ranges[i].low);
    }

    ret = xqc_send_ctl_on_ack_received(conn->conn_send_ctl, &ack_info, packet_in->pkt_recv_time);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_ack_frame|xqc_send_ctl_on_ack_received error|");
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_conn_close_frame|xqc_parse_conn_close_frame error|");
        return ret;
    }

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        ret = xqc_conn_immediate_close(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_conn_close_frame|xqc_conn_immediate_close error|");
            return ret;
        }
    }
    conn->conn_state = XQC_CONN_STATE_DRAINING;

    return XQC_OK;
}

xqc_int_t
xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int ret;
    uint64_t data_limit;

    ret = xqc_parse_data_blocked_frame(packet_in, &data_limit);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_data_blocked_frame|xqc_parse_data_blocked_frame error|");
        return ret;
    }

    ret = xqc_write_max_data_to_packet(conn, data_limit * 2);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_data_blocked_frame|xqc_write_max_data_to_packet error|");
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

    ret = xqc_parse_stream_data_blocked_frame(packet_in, &stream_id, &stream_data_limit);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_data_blocked_frame|xqc_parse_stream_data_blocked_frame error|");
        return ret;
    }

    ret = xqc_write_max_stream_data_to_packet(conn, stream_id, stream_data_limit * 2);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_data_blocked_frame|xqc_write_max_stream_data_to_packet error|");
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_streams_blocked_frame|xqc_parse_streams_blocked_frame error|");
        return ret;
    }

    ret = xqc_write_max_streams_to_packet(conn, stream_limit * 2, bidirectional);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_streams_blocked_frame|xqc_write_max_streams_to_packet error|");
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_max_data_frame|xqc_parse_max_data_frame error|");
        return ret;
    }

    if (max_data > conn->conn_flow_ctl.fc_max_data) {
        conn->conn_flow_ctl.fc_max_data = max_data;
        conn->conn_flag &= ~XQC_CONN_FLAG_DATA_BLOCKED;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_max_data_frame|max_data=%ui|", max_data);
    } else {
        xqc_log(conn->log, XQC_LOG_WARN, "|xqc_process_max_data_frame|max_data too small|");
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_max_stream_data_frame|xqc_parse_max_stream_data_frame error|");
        return ret;
    }

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (stream) {
        if (max_stream_data > stream->stream_flow_ctl.fc_max_stream_data) {
            stream->stream_flow_ctl.fc_max_stream_data = max_stream_data;
            stream->stream_flag &= ~XQC_SF_STREAM_DATA_BLOCKED;
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_process_max_stream_data_frame|max_stream_data=%ui|", max_stream_data);
        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_process_max_stream_data_frame|max_stream_data too small|");
        }

    } else {
        XQC_CONN_ERR(conn, TRA_STREAM_STATE_ERROR);
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
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_max_streams_frame|xqc_parse_max_streams_frame error|");
        return ret;
    }

    if (bidirectional) {
        conn->conn_flow_ctl.fc_max_streams_bidi = max_streams;
    } else {
        conn->conn_flow_ctl.fc_max_streams_uni = max_streams;
    }
    return XQC_OK;
}