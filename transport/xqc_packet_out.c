#include <common/xqc_errno.h>
#include <common/xqc_variable_len_int.h>
#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_send_ctl.h"
#include "xqc_frame_parser.h"
#include "../common/xqc_timer.h"
#include "xqc_packet_parser.h"

xqc_packet_out_t *
xqc_create_packet_out (xqc_send_ctl_t *ctl, enum xqc_pkt_type pkt_type)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;

    /*优先复用已申请*/
    xqc_list_for_each_safe(pos, next, &ctl->ctl_free_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        xqc_send_ctl_remove_free(pos, ctl);

        unsigned char *tmp = packet_out->po_buf;
        memset(packet_out, 0, sizeof(xqc_packet_out_t));
        packet_out->po_buf = tmp;
        goto set_packet;
    }


    packet_out = xqc_calloc(1, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_buf = xqc_malloc(XQC_PACKET_OUT_SIZE + XQC_EXTRA_SPACE + XQC_ACK_SPACE);
    if (!packet_out->po_buf) {
        return NULL;
    }

set_packet:
    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_type = pkt_type;
    packet_out->po_pkt.pkt_pns = xqc_packet_type_to_pns(pkt_type);

    //generate packet number when send
    packet_out->po_pkt.pkt_num = 0;

    xqc_send_ctl_insert_send(&packet_out->po_list, &ctl->ctl_send_packets, ctl);

    return packet_out;
}

void
xqc_destroy_packet_out(xqc_packet_out_t *packet_out)
{
    xqc_free(packet_out->po_buf);
    xqc_free(packet_out);
}

void
xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn)
{
    /* recycle packetout if no frame in it */
    if (packet_out->po_frame_types == 0) {
        xqc_list_del_init(&packet_out->po_list);
        xqc_send_ctl_insert_free(&packet_out->po_list, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
    }
}

int
xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_used_size > 0) {
        return XQC_OK;
    }

    int ret;

    xqc_pkt_type_t pkt_type = packet_out->po_pkt.pkt_type;

    if (pkt_type == XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_short_packet_header(packet_out,
                                          conn->dcid.cid_buf, conn->dcid.cid_len,
                                          XQC_PKTNO_BITS, packet_out->po_pkt.pkt_num);
    } else if (pkt_type != XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_long_packet_header(packet_out,
                                         conn->dcid.cid_buf, conn->dcid.cid_len,
                                         conn->scid.cid_buf, conn->scid.cid_len,
                                         conn->conn_token, conn->conn_token_len,
                                         XQC_QUIC_VERSION, XQC_PKTNO_BITS);
    }
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|gen header error|");
        return ret;
    }
    packet_out->po_used_size += ret;

    return XQC_OK;
}

xqc_packet_out_t*
xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    packet_out = xqc_create_packet_out(conn->conn_send_ctl, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_packet_out error|");
        return NULL;
    }

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    xqc_send_ctl_remove_send(&packet_out->po_list);
    xqc_send_ctl_insert_free(&packet_out->po_list, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
    return NULL;
}

xqc_packet_out_t*
xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    packet_out = xqc_send_ctl_get_packet_out(conn->conn_send_ctl, need, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_get_packet_out error|");
        return NULL;
    }

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    if (packet_out->po_used_size == 0) {
        xqc_send_ctl_remove_send(&packet_out->po_list);
        xqc_send_ctl_insert_free(&packet_out->po_list, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
    }
    return NULL;
}

int
xqc_should_generate_ack(xqc_connection_t *conn)
{
    //xqc_log(conn->log, XQC_LOG_DEBUG, "|should_generate_ack|flag:%s|", xqc_conn_flag_2_str(conn->conn_flag));
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|should_generate_ack yes|flag:%s|",
                xqc_conn_flag_2_str(conn->conn_flag));
        return 1;
    }
    return 0;
}

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns)
{
    int ret, has_gap;
    xqc_packet_number_t largest_ack;
    xqc_msec_t now = xqc_now();

    ret = xqc_gen_ack_frame(conn, packet_out,
                      now, conn->local_settings.ack_delay_exponent, &conn->recv_record[packet_out->po_pkt.pkt_pns], &has_gap, &largest_ack);
    if (ret < 0) {
        goto error;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|ack_size:%ui|", ret);

    packet_out->po_used_size += ret;
    packet_out->po_largest_ack = largest_ack;

    conn->ack_eliciting_pkt[pns] = 0;
    if (has_gap) {
        conn->conn_flag |= XQC_CONN_FLAG_ACK_HAS_GAP;
    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_ACK_HAS_GAP;
    }
    conn->conn_flag &= ~(XQC_CONN_FLAG_SHOULD_ACK_INIT << pns);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_ack_to_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    xqc_pkt_type_t pkt_type;
    xqc_list_head_t *pos;

    int ret;

    for (pns = 0; pns < XQC_PNS_N; ++pns) {
        if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {

            if (pns == XQC_PNS_HSK) {
                pkt_type = XQC_PTYPE_HSK;
            } else if (pns == XQC_PNS_INIT) {
                pkt_type = XQC_PTYPE_INIT;
            } else {
                pkt_type = XQC_PTYPE_SHORT_HEADER;
            }

            xqc_list_for_each(pos, &conn->conn_send_ctl->ctl_send_packets) {
                packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
                if (packet_out->po_pkt.pkt_type == pkt_type) {
                    ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
                    if (ret == -XQC_ENOBUF) {
                        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_write_ack_to_one_packet try new packet|");
                        goto write_new;
                    } else if (ret == XQC_OK){
                        goto done;
                    } else {
                        return ret;
                    }
                }
            }

write_new:
            packet_out = xqc_write_new_packet(conn, pkt_type);
            if (packet_out == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
                return -XQC_ENULLPTR;
            }

            ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_to_one_packet error|ret:%d|", ret);
                return ret;
            }

done:
            xqc_log(conn->log, XQC_LOG_DEBUG, "|pns:%d|", pns);

            //ack packet send first
            xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

        }
    }
    return XQC_OK;
}


int
xqc_write_conn_close_to_packet(xqc_connection_t *conn, unsigned short err_code)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_NUM);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_conn_close_frame(packet_out, err_code, 0, 0);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_conn_close_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 unsigned short err_code, uint64_t final_size)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_reset_stream_frame(packet_out, stream->stream_id, err_code, final_size);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_reset_stream_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    /* new packet with index 0 */
    packet_out->po_stream_frames[0].ps_stream = stream;
    packet_out->po_stream_frames[0].ps_is_reset = 1;
    if (stream->stream_state_send < XQC_SSS_RESET_SENT) {
        stream->stream_state_send = XQC_SSS_RESET_SENT;
    }

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 unsigned short err_code)
{
    int ret;
    xqc_packet_out_t *packet_out;

    /*
     * A STOP_SENDING frame can be sent for streams in the Recv or Size
        Known states
     */
    if (stream->stream_state_recv > XQC_RSS_SIZE_KNOWN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|state error|");
        XQC_CONN_ERR(conn, TRA_STREAM_STATE_ERROR);
        return -XQC_ESTREAM_ST;
    }

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_stop_sending_frame(packet_out, stream->stream_id, err_code);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_stop_sending_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_data_blocked_frame(packet_out, data_limit);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_data_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit)
{
    int ret;
    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_stream_data_blocked_frame(packet_out, stream_id, stream_data_limit);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_stream_data_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_streams_blocked_frame(packet_out, stream_limit, bidirectional);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_streams_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_max_data_frame(packet_out, max_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_data_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t max_stream_data)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_max_stream_data_frame(packet_out, stream_id, max_stream_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_stream_data_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional)
{
    int ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_max_streams_frame(packet_out, max_stream, bidirectional);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_streams_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_new_token_to_packet(xqc_connection_t *conn)
{
    int ret;
    unsigned need;
    xqc_packet_out_t *packet_out;

    unsigned char token[XQC_MAX_TOKEN_LEN];
    unsigned token_len = XQC_MAX_TOKEN_LEN;
    xqc_conn_gen_token(conn, token, &token_len);

    need = 1 //type
            + xqc_vint_get_2bit(token_len) // token len
            + token_len; //token

    packet_out = xqc_write_packet(conn, XQC_PTYPE_INIT, need);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_gen_new_token_frame(packet_out, token, token_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_new_token_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_stream_frame_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
                                 xqc_pkt_type_t pkt_type, uint8_t fin,
                                 const unsigned char *payload, size_t payload_size, size_t *send_data_written)
{
    xqc_packet_out_t *packet_out;
    int n_written;
    packet_out = xqc_write_new_packet(conn, pkt_type);
    if (packet_out == NULL) {
        return -XQC_ENULLPTR;
    }

    n_written = xqc_gen_stream_frame(packet_out,
                                     stream->stream_id, stream->stream_send_offset, fin,
                                     payload,
                                     payload_size,
                                     send_data_written);
    if (n_written < 0) {
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return n_written;
    }
    stream->stream_send_offset += *send_data_written;
    stream->stream_conn->conn_flow_ctl.fc_data_sent += *send_data_written;
    packet_out->po_used_size += n_written;

    for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        if (packet_out->po_stream_frames[i].ps_stream == NULL) {
            packet_out->po_stream_frames[i].ps_stream = stream;
            if (fin && *send_data_written == payload_size) {
                packet_out->po_stream_frames[i].ps_has_fin = 1;
            }
        }
    }

    if (pkt_type == XQC_PTYPE_0RTT) {
        conn->zero_rtt_count++;
    }
    return XQC_OK;
}

void
xqc_process_buff_packets(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        xqc_send_ctl_t *ctl = conn->conn_send_ctl;
        xqc_list_head_t *pos, *next;
        xqc_packet_out_t *packet_out;
        xqc_list_for_each_safe(pos, next, &ctl->ctl_buff_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_process_buff_packets|");
            xqc_send_ctl_remove_buff(pos, ctl);
            xqc_send_ctl_insert_send(pos, &ctl->ctl_send_packets, ctl);
            if (packet_out->po_flag & XQC_POF_DCID_NOT_DONE) {
                xqc_short_packet_update_dcid(packet_out, conn);
            }
        }
    }
}
