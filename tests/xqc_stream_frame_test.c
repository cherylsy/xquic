
#include "xqc_stream_frame_test.h"
#include <CUnit/CUnit.h>
#include "../transport/xqc_conn.h"
#include "../transport/xqc_engine.h"
#include "../transport/xqc_frame.h"

void
xqc_test_stream_frame()
{
    xqc_int_t ret;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT);
    CU_ASSERT(engine != NULL);

    xqc_connection_t *conn = xqc_connect(engine, NULL);
    CU_ASSERT(conn != NULL);

    xqc_stream_t *stream = xqc_create_stream(conn, NULL);
    CU_ASSERT(stream != NULL);

    char payload[100];
    xqc_stream_frame_t *frame[10];
    memset(frame, 0, sizeof(frame));

    for (int i = 0; i < 10; i++) {
        frame[i] = xqc_malloc(sizeof(xqc_stream_frame_t));
        frame[i]->data_length = 10;
        frame[i]->data_offset = i * 10;
        memset(payload + i * 10, i, 10);
        frame[i]->data = xqc_malloc(10);
        memcpy(frame[i]->data, payload + i * 10, 10);
    }

    ret = xqc_insert_stream_frame(conn, stream, frame[1]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[2]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[0]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 30);

    ret = xqc_insert_stream_frame(conn, stream, frame[3]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 40);

    xqc_list_head_t *pos;
    xqc_stream_frame_t *pframe;
    uint64_t offset = 0;
    xqc_list_for_each(pos, &stream->stream_data_in.frames_tailq) {
        pframe = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        CU_ASSERT(pframe->data_offset == offset);
        offset += 10;
    }

    char recv_buf[16];
    unsigned recv_buf_size = 16;
    offset = 0;
    do {
        ret = xqc_stream_recv(stream, recv_buf, recv_buf_size);
        CU_ASSERT(ret >= 0);
        if (ret == 0) {
            break;
        }
        memcmp(payload + offset, recv_buf, ret);
        offset += ret;
    } while (ret > 0);


}