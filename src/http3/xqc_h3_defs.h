#ifndef _XQC_H3_DEFS_H_
#define _XQC_H3_DEFS_H_

#define XQC_H3_MAX_FIELD_SECTION_SIZE   (32 * 1024)

#define XQC_VAR_BUF_INIT_SIZE (256)

#define XQC_VAR_BUF_CUT_SIZE (16 * 1024)

#define XQC_DATA_BUF_SIZE_4K (4096)

#define XQC_H3_STREAM_MAX_FRM_PAYLOAD (4096)

#define XQC_H3_MAX_BUFFER_COUNT_SIZE (100)


/* setting options */
typedef enum {
    /* h3 settings */
    XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06,

    /* QPACK settings */
    XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01,
    XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS = 0x07,
} xqc_h3_settings_id;


#endif
