
#include <common/xqc_log.h>
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_transport.h"
#include "common/xqc_log.h"
#include "xqc_packet_in.h"
#include "xqc_conn.h"
#include "xqc_frame_parser.h"
#include "xqc_send_ctl.h"


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
    [XQC_FRAME_MAX_STREAM_DAT]      = "MAX_STREAM_DAT",
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
xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned char *last_pos = NULL;

    while (packet_in->pos < packet_in->last) {
        last_pos = packet_in->pos;

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
            default:
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|unknown frame type|");
                return XQC_ERROR;
        }

        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|process frame error|");
            return XQC_ERROR;
        }

        if (last_pos == packet_in->pos) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_frames|pos not update|");
            return XQC_ERROR;
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
        return XQC_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    ret = xqc_parse_stream_frame(packet_in, conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_stream_frame|xqc_parse_stream_frame error|");
        return XQC_ERROR;
    }

    return XQC_OK;
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
        return XQC_ERROR;
    }

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_in->pi_pkt.pkt_type);
    xqc_stream_t *stream = conn->crypto_stream[encrypt_level];
    if (stream) {
        xqc_stream_ready_to_read(stream);
    } else {
        conn->crypto_stream[encrypt_level] = xqc_create_crypto_stream(conn, encrypt_level, NULL);
        if (conn->crypto_stream[encrypt_level] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_crypto_frame|xqc_create_crypto_stream err|");
            return XQC_ERROR;
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
        return XQC_ERROR;
    }

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_ack_frame|high: %ui, low: %ui|",
        ack_info.ranges[i].high, ack_info.ranges[i].low);
    }

    ret = xqc_send_ctl_on_ack_received(conn->conn_send_ctl, &ack_info, packet_in->pkt_recv_time);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_ack_frame|xqc_send_ctl_on_ack_received error|");
        return XQC_ERROR;
    }

    return XQC_OK;
}