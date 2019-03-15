#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "../common/xqc_types.h"
#include "xqc_packet_out.h"

ssize_t
xqc_stream_send (xqc_connection_t *c,
                 xqc_stream_t *stream,
                 unsigned char *send_data,
                 size_t send_data_size,
                 uint8_t fin)
{
    size_t send_data_offset = 0;
    size_t send_data_written = 0;
    unsigned int n_written = 0;

    while (send_data_offset < send_data_size) {
        //TODO find or create a packet to write
        xqc_packet_out_t *packet_out;


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
                                         stream->stream_id, send_data_offset, 0,
                                         send_data + send_data_offset,
                                         send_data_size - send_data_offset,
                                         &send_data_written);

        send_data_offset += send_data_written;
        packet_out->po_used_size += n_written;
    }
    return send_data_offset;
}

