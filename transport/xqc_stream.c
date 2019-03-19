#include "xqc_conn.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_transport.h"
#include "xqc_packet_out.h"
#include "xqc_send_ctl.h"

ssize_t
xqc_stream_send (xqc_connection_t *c,
                 uint64_t stream_id,
                 unsigned char *send_data,
                 size_t send_data_size,
                 uint8_t fin)
{
    size_t send_data_offset = 0;
    size_t send_data_written = 0;
    unsigned int n_written = 0;
    xqc_packet_out_t *packet_out;

    while (send_data_offset < send_data_size) {
        //TODO find or create a packet to write
        packet_out = xqc_send_ctl_get_packet_out(c->conn_send_ctl, PNS_01RTT);
        if (packet_out == NULL) {
            return -1;
        }


        //TODO calc packet_number_bits and packet_number
        unsigned char packet_number_bits;

        //check if header is created
        if (!packet_out->po_used_size) {
            n_written = xqc_gen_short_packet_header(packet_out->po_buf,
                                                    packet_out->po_buf_size - packet_out->po_used_size,
                                                    c->dcid.cid_buf, c->dcid.cid_len,
                                                    packet_number_bits, packet_out->po_pktno);

            packet_out->po_used_size += n_written;
        }

        n_written = xqc_gen_stream_frame(packet_out->po_buf + packet_out->po_used_size,
                                         packet_out->po_buf_size - packet_out->po_used_size,
                                         stream_id, send_data_offset, fin,
                                         send_data + send_data_offset,
                                         send_data_size - send_data_offset,
                                         &send_data_written);

        send_data_offset += send_data_written;
        packet_out->po_used_size += n_written;
    }
    return send_data_offset;
}

