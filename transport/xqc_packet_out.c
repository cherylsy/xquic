#include <common/xqc_errno.h>
#include "xqc_packet_out.h"
#include "xqc_conn.h"
#include "../common/xqc_memory_pool.h"
#include "xqc_send_ctl.h"
#include "xqc_frame_parser.h"
#include "../common/xqc_timer.h"
#include "xqc_packet_parser.h"

#define XQC_PACKET_OUT_SIZE 1280    //TODO 先写死

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

    packet_out->po_buf = xqc_malloc(XQC_PACKET_OUT_SIZE);
    if (!packet_out->po_buf) {
        return NULL;
    }

set_packet:
    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_type = pkt_type;
    packet_out->po_pkt.pkt_pns = xqc_packet_type_to_pns(pkt_type);

    //generate packet number when send
    packet_out->po_pkt.pkt_num = 0;

    xqc_send_ctl_insert_send(&packet_out->po_list, &ctl->ctl_packets, ctl);

    return packet_out;
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
                                         NULL, 0,
                                         XQC_QUIC_VERSION, XQC_PKTNO_BITS);
    }
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets gen header error");
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
    packet_out = xqc_create_packet_out(conn->conn_send_ctl, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_new_packet xqc_create_packet_out error");
        return NULL;
    }

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_new_packet xqc_write_packet_header error");
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
    packet_out = xqc_send_ctl_get_packet_out(conn->conn_send_ctl, need, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_packet xqc_send_ctl_get_packet_out error");
        return NULL;
    }

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_packet xqc_write_packet_header error");
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
    //xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_should_generate_ack|flag=%s|", xqc_conn_flag_2_str(conn->conn_flag));
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_should_generate_ack yes|flag=%s|",
                xqc_conn_flag_2_str(conn->conn_flag));
        return 1;
    }
    return 0;
}

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns)
{
    int size, has_gap;
    xqc_packet_number_t largest_ack;
    xqc_msec_t now = xqc_gettimeofday();


    size = xqc_gen_ack_frame(conn, packet_out,
                      now, conn->trans_param.ack_delay_exponent, &conn->recv_record[packet_out->po_pkt.pkt_pns], &has_gap, &largest_ack);
    if (size < 0) {
        return size;
    }

    packet_out->po_used_size += size;
    packet_out->po_largest_ack = largest_ack;

    xqc_long_packet_update_length(packet_out);

    conn->ack_eliciting_pkt[pns] = 0;
    if (has_gap) {
        conn->conn_flag |= XQC_CONN_FLAG_ACK_HAS_GAP;
    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_ACK_HAS_GAP;
    }
    conn->conn_flag &= ~(XQC_CONN_FLAG_SHOULD_ACK_INIT << pns);

    return XQC_OK;
}

int
xqc_write_ack_to_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    xqc_pkt_type_t pkt_type;

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

            packet_out = xqc_write_new_packet(conn, pkt_type);
            if (packet_out == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets xqc_write_new_packet error");
                return -XQC_ENULLPTR;
            }

            ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_ack_to_packets xqc_write_ack_to_one_packet error");
                return ret;
            }

            xqc_log(conn->log, XQC_LOG_DEBUG, "xqc_write_ack_to_packets pns=%d", pns);

            //ack packet send first
            xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_packets);

        }
    }
    return XQC_OK;
}


int
xqc_write_conn_close_to_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, unsigned short err_code)
{
    int ret;

    ret = xqc_gen_conn_close_frame(packet_out, err_code, 0, 0);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "xqc_write_conn_close_to_packet error");
        return ret;
    }

    packet_out->po_used_size += ret;

    xqc_long_packet_update_length(packet_out);

    return XQC_OK;
}