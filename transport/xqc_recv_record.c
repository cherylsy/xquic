
#include "xqc_recv_record.h"
#include "xqc_packet.h"
#include "xqc_conn.h"
#include "xqc_send_ctl.h"
#include "common/xqc_log.h"

void
xqc_recv_record_log(xqc_connection_t *conn, xqc_recv_record_t *recv_record)
{
    xqc_list_head_t *pos;
    xqc_pktno_range_node_t *pnode;
    xqc_list_for_each(pos, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|low:%ui|high:%ui|",
                pnode->pktno_range.low, pnode->pktno_range.high);
    }
}

static int
xqc_pktno_range_can_merge (xqc_pktno_range_node_t *node, xqc_packet_number_t packet_number)
{
    if (node->pktno_range.low - 1 == packet_number) {
        --node->pktno_range.low;
        return 1;
    }
    if (node->pktno_range.high + 1 == packet_number) {
        ++node->pktno_range.high;
        return 1;
    }
    return 0;
}

/**
 * insert into range list when receive a new packet
 */
xqc_pkt_range_status
xqc_recv_record_add (xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number,
                     xqc_msec_t recv_time)
{
    xqc_list_head_t *pos, *prev;
    xqc_pktno_range_node_t *pnode, *prev_node;
    xqc_pktno_range_t range;
    pnode = prev_node = NULL;
    pos = prev = NULL;

    xqc_pktno_range_node_t *first = NULL;
    xqc_list_for_each(pos, &recv_record->list_head) {
        first = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        break;
    }
    if (first && packet_number > first->pktno_range.high) {
        recv_record->largest_pkt_recv_time = recv_time;
    }

    xqc_list_for_each(pos, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        if (packet_number <= pnode->pktno_range.high) {
            if (packet_number >= pnode->pktno_range.low) {
                return XQC_PKTRANGE_DUP;
            }
        } else {
            break;
        }
        prev = pos;
    }

    if (pos && !xqc_list_empty(&recv_record->list_head)) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
    }
    if (prev) {
        prev_node = xqc_list_entry(prev, xqc_pktno_range_node_t, list);
    }

    if ((prev && xqc_pktno_range_can_merge(prev_node, packet_number)) ||
        (pnode && xqc_pktno_range_can_merge(pnode, packet_number))) {
        if (prev_node && pnode && (prev_node->pktno_range.low - 1 == pnode->pktno_range.high)) {
            prev_node->pktno_range.low = pnode->pktno_range.low;
            xqc_list_del_init(pos);
            xqc_free(pnode);
        }
    } else {
        xqc_pktno_range_node_t *new_node = xqc_calloc(1, sizeof(*new_node));
        if (!new_node) {
            return XQC_PKTRANGE_ERR;
        }
        new_node->pktno_range.low = new_node->pktno_range.high = packet_number;
        if (pos) {
            //insert before pos
            xqc_list_add_tail(&(new_node->list), pos);
        } else {
            //insert tail of the list
            xqc_list_add_tail(&(new_node->list), &recv_record->list_head);
        }
    }

    return XQC_PKTRANGE_OK;
}

/**
 * del packet number range < del_from
 */
void
xqc_recv_record_del (xqc_recv_record_t *recv_record, xqc_packet_number_t del_from)
{
    if (del_from < recv_record->rr_del_from) {
        return;
    }

    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_pktno_range_t *range;

    recv_record->rr_del_from = del_from;

    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        range = &pnode->pktno_range;

        if (range->low < del_from) {
            if (range->high < del_from) {
                xqc_list_del_init(pos);
                xqc_free(pnode);
            } else {
                range->low = del_from;
            }
        }
    }
}

void
xqc_recv_record_destroy(xqc_recv_record_t *recv_record)
{
    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
            xqc_list_del_init(pos);
            xqc_free(pnode);
    }
}

xqc_packet_number_t
xqc_recv_record_largest(xqc_recv_record_t *recv_record)
{
    xqc_pktno_range_node_t *pnode = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        break;
    }

    if (pnode) {
        return pnode->pktno_range.high;
    } else {
        return 0;
    }
}

void
xqc_maybe_should_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns, int out_of_order, xqc_msec_t now)
{
    /* Generating Acknowledgements

   QUIC SHOULD delay sending acknowledgements in response to packets,
   but MUST NOT excessively delay acknowledgements of ack-eliciting
   packets.  Specifically, implementations MUST attempt to enforce a
   maximum ack delay to avoid causing the peer spurious timeouts.  The
   maximum ack delay is communicated in the "max_ack_delay" transport
   parameter and the default value is 25ms.

   An acknowledgement SHOULD be sent immediately upon receipt of a
   second ack-eliciting packet.  QUIC recovery algorithms do not assume
   the peer sends an ACK immediately when receiving a second ack-
   eliciting packet.

   In order to accelerate loss recovery and reduce timeouts, the
   receiver SHOULD send an immediate ACK after it receives an out-of-
   order packet.  It could send immediate ACKs for in-order packets for
   a period of time that SHOULD NOT exceed 1/8 RTT unless more out-of-
   order packets arrive.  If every packet arrives out-of- order, then an
   immediate ACK SHOULD be sent for every received packet.

   Similarly, packets marked with the ECN Congestion Experienced (CE)
   codepoint in the IP header SHOULD be acknowledged immediately, to
   reduce the peer's response time to congestion events.

   As an optimization, a receiver MAY process multiple packets before
   sending any ACK frames in response.  In this case the receiver can
   determine whether an immediate or delayed acknowledgement should be
   generated after processing incoming packets.
    */
    /*xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_maybe_should_ack?|out_of_order=%d|ack_eliciting_pkt=%d|pns=%d|flag=%s|",
            out_of_order, conn->ack_eliciting_pkt[pns], pns, xqc_conn_flag_2_str(conn->conn_flag));*/

    if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|already yes|");
        return;
    }


    if(pns == XQC_PNS_HSK && (xqc_tls_check_hs_tx_key_ready(conn) == 0)){
        xqc_log(conn->log, XQC_LOG_DEBUG, "|handshake ack should send after tx key ready|");
        return;
    } else if (pns == XQC_PNS_01RTT && !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|01RTT ack should send after handshake complete|");
        return;
    }

    if (conn->ack_eliciting_pkt[pns] >= 2
        || (pns <= XQC_PNS_HSK && conn->ack_eliciting_pkt[pns] >= 1)
        || (out_of_order && conn->ack_eliciting_pkt[pns] >= 1)) {

        conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;
        xqc_send_ctl_timer_unset(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|yes|out_of_order:%d|ack_eliciting_pkt:%d|"
                                          "pns:%d|flag:%s|",
                out_of_order, conn->ack_eliciting_pkt[pns],
                pns, xqc_conn_flag_2_str(conn->conn_flag));
    } else if (conn->ack_eliciting_pkt[pns] > 0 &&
               !xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns)) {
        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns,
                               now + conn->local_settings.max_ack_delay*1000);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|set ack timer|ack_eliciting_pkt:%d|pns:%d|"
                                          "flag:%s|now:%ui|max_ack_delay:%ui|",
                conn->ack_eliciting_pkt[pns], pns, xqc_conn_flag_2_str(conn->conn_flag),
                now, conn->local_settings.max_ack_delay*1000);
    }
}
