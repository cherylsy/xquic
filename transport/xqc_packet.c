
#include "../include/xquic.h"
#include "xqc_packet.h"
#include "xqc_conn.h"



xqc_int_t
xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid,
                             unsigned char *buf, size_t size)
{
    unsigned char *pos = NULL;

    if (size <= 0) {
        return XQC_ERROR;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(buf)) {

        /* TODO: fix me, variable length */
        if (size < 1 + XQC_DEFAULT_CID_LEN) {
            return XQC_ERROR;
        }

        xqc_cid_set(dcid, buf + 1, XQC_DEFAULT_CID_LEN);
        
        return XQC_OK;
    }

    /* long header */
    if (size < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH) {
        return XQC_ERROR;
    }

    pos = buf + 1 + XQC_PACKET_VERSION_LENGTH;
    dcid->cid_len = XQC_PACKET_LONG_HEADER_GET_DCIL(pos);
    scid->cid_len = XQC_PACKET_LONG_HEADER_GET_SCIL(pos);
    pos += 1;

    if (dcid->cid_len) {
        dcid->cid_len += 3;
    }

    if (scid->cid_len) {
        scid->cid_len += 3;
    }

    if (size < XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
               + dcid->cid_len + scid->cid_len) 
    {
        return XQC_ERROR;    
    }

    xqc_memcpy(dcid->cid_buf, pos, dcid->cid_len);
    pos += dcid->cid_len;

    xqc_memcpy(scid->cid_buf, pos, scid->cid_len);
    pos += scid->cid_len;  

    return XQC_OK;
}


ssize_t
xqc_conn_process_single_packet(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    ssize_t res = 0;

    if (xqc_conn_check_handshake_completed(c)) {

    }

    return res;
}


/**
 * 1 UDP payload = n QUIC packets
 */
xqc_int_t
xqc_conn_process_packets(xqc_connection_t *c,
                          xqc_packet_in_t *packet_in)
{
    ssize_t res = 0;

    while (packet_in->pos < packet_in->last) {

        res = xqc_conn_process_single_packet(c, packet_in);

        /* err in parse packet, TODO: res == 0 */
        if (res <= 0) {
            xqc_log(c->log, XQC_LOG_WARN, "process packets err|%zd|%p|%p|%zu|", 
                                          res, (void *)packet_in->pos,
                                          (void *)packet_in->buf, packet_in->buf_size);
            return XQC_ERROR;
        }

        packet_in->pos += (size_t)res;
    }

    return XQC_OK;
}


