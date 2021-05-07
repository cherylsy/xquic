#ifndef XQC_DEFS_H
#define XQC_DEFS_H

#define XQC_MAX_PACKET_LEN 1500

/* default connection timeout(millisecond) */
#define XQC_CONN_DEFAULT_IDLE_TIMEOUT 120000

#define XQC_CONN_ADDR_VALIDATION_CID_ENTROPY    8

/* connection PTO packet count */
#define XQC_CONN_PTO_PKT_CNT_MAX    2

/* connection active cid limit */
#define XQC_CONN_SETTINGS_ACTIVE_CID_LIMIT  8

#endif