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
    TRA_HS_CERTIFICATE_VERIFY_FAIL =  0x1FE, /* for handshake certifacate verify error */
    TRA_CRYPTO_ERROR               =  0x1FF, /* 0x1XX */
} xqc_trans_err_code_t;

/* https://tools.ietf.org/html/draft-ietf-quic-http-29#section-8.1 */
typedef enum
{
    H3_NO_ERROR                   = 0x100,
    H3_GENERAL_PROTOCOL_ERROR     = 0x101,
    H3_INTERNAL_ERROR             = 0x102,
    H3_STREAM_CREATION_ERROR      = 0x103,
    H3_CLOSED_CRITICAL_STREAM     = 0x104,
    H3_FRAME_UNEXPECTED           = 0x105,
    H3_FRAME_ERROR                = 0x106,
    H3_EXCESSIVE_LOAD             = 0x107,
    H3_ID_ERROR                   = 0x108,
    H3_SETTINGS_ERROR             = 0x109,
    H3_MISSING_SETTINGS           = 0x10A,
    H3_REQUEST_REJECTED           = 0x10B,
    H3_REQUEST_CANCELLED          = 0x10C,
    H3_REQUEST_INCOMPLETE         = 0x10D,
    H3_CONNECT_ERROR              = 0x10F,
    H3_VERSION_FALLBACK           = 0x110,
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
#define XQC_EDUP_FRAME      627 //重复的帧


//xquic tls error code, for call
#define XQC_EARLY_DATA_REJECT (-770)
#define XQC_ENCRYPT_DATA_ERROR  (-790)
#define XQC_DECRYPT_DATA_ERROR  (-791)
#define XQC_TLS_CLIENT_INITIAL_ERROR (-780)
#define XQC_TLS_CLIENT_REINTIAL_ERROR (-781)



/* For HTTP3 application 8xx */
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
#define XQC_H3_BUFFER_EXCEED    812 //http send buffer 超过最大值

#define XQC_H3_DECODE_ERROR     815 //解码失败
#define XQC_H3_INVALID_STREAM   816 //stream非法，如多个control stream等
#define XQC_H3_CLOSE_CRITICAL_STREAM 817 //非法关闭control stream、qpack encoder/decoder stream
#define XQC_H3_STATE_ERROR      818 //http3 解码状态出错
#define XQC_H3_CONTROL_ERROR    819  //control stream error, such as setting not send first or send twice
#define XQC_H3_CONTROL_DECODE_ERROR     820 //control stream 解码错误，如遇到无法识别的frame type
#define XQC_H3_CONTROL_DECODE_INVALID   821  // control stream decoder invalid, 例如剩余长度非法
#define XQC_H3_PRIORITY_ERROR   822 //优先级相关错误

#define XQC_H3_INVALID_FRAME_TYPE   830
#define XQC_H3_UNSUPPORT_FRAME_TYPE 831

#define XQC_QPACK_DECODER_VARINT_ERROR  850  //qpack 解码变长整数失败
#define XQC_QPACK_ENCODER_ERROR         851 //qpack编码过程中出错
#define XQC_QPACK_DECODER_ERROR         852 //qpack解码过程中出错
#define XQC_QPACK_DYNAMIC_TABLE_ERROR   853 //qpack动态表错误
#define XQC_QPACK_STATIC_TABLE_ERROR    854 //qpack静态表相关错误
#define XQC_QPACK_SET_DTABLE_CAP_ERROR  855 //qpack设置动态表容量出错
#define XQC_QPACK_SEND_ERROR            856 //qpack 发送数据或者控制报文出错
#define XQC_QPACK_SAVE_HEADERS_ERROR    857 //qpack 保存name-value到header结构体中时出错


#endif /* _XQC_ERRNO_H_INCLUDED_ */

