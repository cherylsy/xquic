#ifndef _XQC_H3_REQUEST_H_INCLUDED_
#define _XQC_H3_REQUEST_H_INCLUDED_

#include "src/http3/xqc_h3_stream.h"

typedef enum{
    //XQC_H3_REQUEST_HEADER_COMPLETE_RECV = 1 << 0,
    //XQC_H3_REQUEST_HEADER_ALREADY_READ  = 1 << 1,
    XQC_H3_REQUEST_HEADER_FIN           = 1 << 2,
    //XQC_H3_REQUEST_HEADER_CAN_READ      = 1 << 3,
    XQC_H3_REQUEST_BODY_CAN_READ        = 1 << 4,
}xqc_h3_request_flag;


typedef enum{
    XQC_H3_REQUEST_HEADER_DATA_NONE     = 0,
    XQC_H3_REQUEST_HEADER_DATA_CURSOR_0 = 1,
    XQC_H3_REQUEST_HEADER_DATA_CURSOR_1 = 2,
}xqc_h3_request_header_read_flag;


#define XQC_H3_REQUEST_HEADER_MASK 1
typedef struct xqc_h3_request_header{
    xqc_http_headers_t headers[2]; //
    uint8_t read_flag;
    uint8_t writing_cursor;
}xqc_h3_request_header_t;

typedef struct xqc_h3_request_s {
    xqc_h3_stream_t     *h3_stream;
    void                *user_data;
    //xqc_http_headers_t  headers; //链表，增加是否已读的flag
    xqc_h3_request_header_t h3_header;
    int                 flag;

    xqc_h3_request_callbacks_t
                        *request_if;
    size_t              body_recvd;
    size_t              body_recvd_final_size;
    size_t              body_sent;
    size_t              body_sent_final_size;
} xqc_h3_request_t;

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request);

xqc_h3_request_t *
xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data);
int xqc_h3_request_header_notify_read(xqc_h3_request_header_t * h3_header);

#endif /* _XQC_H3_REQUEST_H_INCLUDED_ */
