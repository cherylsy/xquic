
#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_


#include <errno.h>

typedef enum
{
    TRA_NO_ERROR                   =  0x0,
    TRA_INTERNAL_ERROR             =  0x1,
    TRA_SERVER_BUSY                =  0x2,
    TRA_FLOW_CONTROL_ERROR         =  0x3,
    TRA_STREAM_LIMIT_ERROR         =  0x4,
    TRA_STREAM_STATE_ERROR         =  0x5,
    TRA_FINAL_SIZE_ERROR           =  0x6,
    TRA_FRAME_ENCODING_ERROR       =  0x7,
    TRA_TRANSPORT_PARAMETER_ERROR  =  0x8,
    TRA_VERSION_NEGOTIATION_ERROR  =  0x9,
    TRA_PROTOCOL_VIOLATION         =  0xA,
    TRA_INVALID_MIGRATION          =  0xC,
    TRA_CRYPTO_BUFFER_EXCEEDED     =  0xD,
    TRA_CRYPTO_ERROR               =  0x100,
} xqc_trans_err_code_t;

typedef enum
{
    HTTP_NO_ERROR                   = 0x00,
    HTTP_GENERAL_PROTOCOL_ERROR     = 0x01,
    HTTP_INTERNAL_ERROR             = 0x03,
    HTTP_REQUEST_CANCELLED          = 0x05,
    HTTP_INCOMPLETE_REQUEST         = 0x06,
    HTTP_CONNECT_ERROR              = 0x07,
    HTTP_EXCESSIVE_LOAD             = 0x08,
    HTTP_VERSION_FALLBACK           = 0x09,
    HTTP_WRONG_STREAM               = 0x0A,
    HTTP_ID_ERROR                   = 0x0B,
    HTTP_STREAM_CREATION_ERROR      = 0x0D,
    HTTP_CLOSED_CRITICAL_STREAM     = 0x0F,
    HTTP_EARLY_RESPONSE             = 0x0011,
    HTTP_MISSING_SETTINGS           = 0x0012,
    HTTP_UNEXPECTED_FRAME           = 0x0013,
    HTTP_REQUEST_REJECTED           = 0x0014,
    HTTP_SETTINGS_ERROR             = 0x00FF,
    HTTP_MALFORMED_FRAME            = 0x0100,
} xqc_h3_err_code_t;

#define XQC_EAGAIN        EAGAIN

/* For QUIC transport 6xx */
#define XQC_ENOBUF          600 //buf空间不足
#define XQC_EVINTREAD       601 //读取变长整数失败，一般是包格式不合法
#define XQC_ENULLPTR        602 //空指针，一般是申请内存失败
#define XQC_EMALLOC         603 //申请内存失败
#define XQC_EILLPKT         604 //非法报文
#define XQC_ELEVEL          605 //加密等级错误
#define XQC_ECREATE_CONN    606 //创建连接失败
#define XQC_CLOSING         607 //连接正在关闭，拒绝操作
#define XQC_ECONN_NFOUND    608 //找不到对应连接
#define XQC_ESYS            609 //系统错误，一般是公共库接口失败
#define XQC_EBLOCKED        610 //写阻塞，类似EAGAIN
#define XQC_EPARAM          611 //参数错误
#define XQC_ESTATE          612 //连接状态异常
#define XQC_ELIMIT          613 //超过缓存限制
#define XQC_EPROTO          614 //违反协议规定
#define XQC_ESOCKET         615 //socket接口失败
#define XQC_EFATAL          616 //致命错误，框架会立即destroy连接
#define XQC_ESTREAM_ST      617 //流状态异常
#define XQC_ESEND_RETRY     618 //发送retry失败
#define XQC_ECONN_BLOCKED   619 //连接级流控
#define XQC_ESTREAM_BLOCKED 620 //流级流控
#define XQC_EENCRYPT        621 //加密失败
#define XQC_EDECRYPT        622 //解密失败

/* For QUIC ssl 7xx */


/* For QUIC application 8xx */
#define XQC_H3_EMALLOC      800
#define XQC_H3_ESTREAM      801
#define XQC_H3_EREQUEST     802
#define XQC_H3_EGOAWAY      803




#endif /* _XQC_ERRNO_H_INCLUDED_ */

