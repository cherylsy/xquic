
#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_

/* https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-20 */
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
    TRA_CRYPTO_ERROR               =  0x1FF,//0x1XX
} xqc_trans_err_code_t;

/* https://tools.ietf.org/html/draft-ietf-quic-http-23#section-8.1 */
typedef enum
{
    HTTP_NO_ERROR                   = 0x100,
    HTTP_GENERAL_PROTOCOL_ERROR     = 0x101,
    HTTP_INTERNAL_ERROR             = 0x102,
    HTTP_STREAM_CREATION_ERROR      = 0x103,
    HTTP_CLOSED_CRITICAL_STREAM     = 0x104,
    HTTP_FRAME_UNEXPECTED           = 0x105,
    HTTP_FRAME_ERROR                = 0x106,
    HTTP_EXCESSIVE_LOAD             = 0x107,
    HTTP_ID_ERROR                   = 0x108,
    HTTP_SETTINGS_ERROR             = 0x109,
    HTTP_MISSING_SETTINGS           = 0x10A,
    HTTP_REQUEST_REJECTED           = 0x10B,
    HTTP_REQUEST_CANCELLED          = 0x10C,
    HTTP_REQUEST_INCOMPLETE         = 0x10D,
    HTTP_EARLY_RESPONSE             = 0x10E,
    HTTP_CONNECT_ERROR              = 0x10F,
    HTTP_VERSION_FALLBACK           = 0x110,
} xqc_h3_err_code_t;


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
#define XQC_EAGAIN          610 //写阻塞，类似EAGAIN
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
#define XQC_ESTREAM_NFOUND  623 //找不到对应流
#define XQC_EWRITE_PKT      624 //创建包或写包头失败
#define XQC_ECREATE_STREAM  625 //创建流失败
#define XQC_ESTREAM_RESET   626 //流已被reset


/* For QUIC application 8xx */
#define XQC_H3_EMALLOC          800 //申请内存失败
#define XQC_H3_ECREATE_STREAM   801 //创建流失败
#define XQC_H3_ECREATE_REQUEST  802 //创建请求失败
#define XQC_H3_EGOAWAY_RECVD    803 //接收到GOAWAY，拒绝操作
#define XQC_H3_ECREATE_CONN     804 //创建连接失败
#define XQC_H3_EQPACK_ENCODE    805 //QPACK编码失败
#define XQC_H3_EQPACK_DECODE    806 //QPACK解码失败
#define XQC_H3_EPRI_TREE        807 //优先级树失败
#define XQC_H3_EPROC_CONTROL    808 //处理control流失败
#define XQC_H3_EPROC_REQUEST    809 //处理request流失败
#define XQC_H3_EPROC_PUSH       810 //处理push流失败
#define XQC_H3_EPARAM           811 //参数错误



#endif /* _XQC_ERRNO_H_INCLUDED_ */

