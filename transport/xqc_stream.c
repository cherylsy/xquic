#include "xqc_conn.h"
#include "xqc_stream.h"
#include "xqc_packet_parser.h"
#include "xqc_frame_parser.h"
#include "xqc_transport.h"
#include "xqc_packet_out.h"
#include "xqc_send_ctl.h"
#include "xqc_frame.h"

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

xqc_stream_t *
xqc_create_stream (xqc_connection_t *conn,
                  void *user_data)
{
    xqc_stream_t *stream = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    xqc_stream_id_t stream_id;
    stream->stream_id_type = XQC_CLI_BID;
    stream->stream_id = xqc_gen_stream_id(conn, stream->stream_id_type);
    stream->stream_conn = conn;
    stream->stream_if = &conn->engine->eng_callback;
    stream->user_data = user_data;

    xqc_id_hash_element_t e = {stream_id, stream};
    if (xqc_id_hash_add(conn->streams_hash, e)) {
        return NULL;
    }

    TAILQ_INSERT_TAIL(&conn->conn_write_streams, stream, next_write_stream);
    return stream;
}


ssize_t
xqc_stream_send (xqc_connection_t *c,
                 xqc_stream_t *stream,
                 unsigned char *send_data,
                 size_t send_data_size,
                 uint8_t fin)
{
    size_t send_data_written = 0;
    size_t offset = 0; //本次send_data中的已写offset
    int n_written = 0;
    xqc_packet_out_t *packet_out;
    uint8_t fin_only = fin && !send_data_size;

    while (offset < send_data_size || fin_only) {
        unsigned int header_size = xqc_stream_frame_header_size(stream->stream_id,
                                                                stream->stream_send_offset,
                                                                send_data_size - offset);
        packet_out = xqc_send_ctl_get_packet_out(c->conn_send_ctl, header_size + 1, PNS_01RTT);
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
        packet_out->po_used_size += n_written;
        fin_only = 0;
    }
    return stream->stream_send_offset;
}

void
xqc_process_write_streams (xqc_connection_t *conn)
{
    xqc_stream_t *stream;
    TAILQ_FOREACH(stream, &conn->conn_write_streams, next_write_stream) {
        stream->stream_if->stream_write_notify(stream->user_data, stream->stream_id);
    }
}

void
xqc_process_read_streams (xqc_connection_t *conn)
{
    xqc_stream_t *stream;
    TAILQ_FOREACH(stream, &conn->conn_read_streams, next_read_stream) {
        stream->stream_if->stream_read_notify(stream->user_data, stream->stream_id);
    }
}
