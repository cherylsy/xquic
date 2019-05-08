
#include <common/xqc_log.h>
#include "xqc_frame.h"
#include "../include/xquic_typedef.h"
#include "../common/xqc_variable_len_int.h"
#include "xqc_transport.h"
#include "common/xqc_log.h"
#include "xqc_packet_in.h"
#include "xqc_conn.h"
#include "xqc_frame_parser.h"

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
    packet_in->pi_frame_types |= XQC_FRAME_BIT_PADDING;
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
    packet_in->pi_frame_types |= XQC_FRAME_BIT_STREAM;
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
    packet_in->pi_frame_types |= XQC_FRAME_BIT_CRYPTO;
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
    packet_in->pi_frame_types |= XQC_FRAME_BIT_ACK;
    xqc_ack_info_t ack_info;
    ret = xqc_parse_ack_frame(packet_in, conn, &ack_info);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_ack_frame|xqc_parse_stream_frame error|");
        return XQC_ERROR;
    }
    return XQC_OK;
}