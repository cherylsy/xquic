#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_

/**
 *  QUIC Transport Protocol error codes [Transport] draft-29
 *  https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-20
 */
typedef enum {
    TRA_NO_ERROR                    =  0x0,
    TRA_INTERNAL_ERROR              =  0x1,
    TRA_CONNECTION_REFUSED_ERROR    =  0x2,
    TRA_FLOW_CONTROL_ERROR          =  0x3,
    TRA_STREAM_LIMIT_ERROR          =  0x4,
    TRA_STREAM_STATE_ERROR          =  0x5,
    TRA_FINAL_SIZE_ERROR            =  0x6,
    TRA_FRAME_ENCODING_ERROR        =  0x7,
    TRA_TRANSPORT_PARAMETER_ERROR   =  0x8,
    TRA_CONNECTION_ID_LIMIT_ERROR   =  0x9,
    TRA_PROTOCOL_VIOLATION          =  0xA,
    TRA_INVALID_TOKEN               =  0xB,
    TRA_APPLICATION_ERROR           =  0xC,
    TRA_CRYPTO_BUFFER_EXCEEDED      =  0xD,
    TRA_HS_CERTIFICATE_VERIFY_FAIL  =  0x1FE, /* for handshake certifacate verify error */
    TRA_CRYPTO_ERROR                =  0x1FF, /* 0x1XX */
} xqc_trans_err_code_t;

/**
 *  QUIC Http/3 Protocol error codes [HTTP3] draft-29
 *  https://tools.ietf.org/html/draft-ietf-quic-http-29#section-8.1
 */
typedef enum {
    H3_NO_ERROR                     = 0x100,
    H3_GENERAL_PROTOCOL_ERROR       = 0x101,
    H3_INTERNAL_ERROR               = 0x102,
    H3_STREAM_CREATION_ERROR        = 0x103,
    H3_CLOSED_CRITICAL_STREAM       = 0x104,
    H3_FRAME_UNEXPECTED             = 0x105,
    H3_FRAME_ERROR                  = 0x106,
    H3_EXCESSIVE_LOAD               = 0x107,
    H3_ID_ERROR                     = 0x108,
    H3_SETTINGS_ERROR               = 0x109,
    H3_MISSING_SETTINGS             = 0x10A,
    H3_REQUEST_REJECTED             = 0x10B,
    H3_REQUEST_CANCELLED            = 0x10C,
    H3_REQUEST_INCOMPLETE           = 0x10D,
    H3_CONNECT_ERROR                = 0x10F,
    H3_VERSION_FALLBACK             = 0x110,
} xqc_h3_err_code_t;


#define XQC_OK      0
#define XQC_ERROR   -1


/* xquic transport internal error codes: 6xx */
typedef enum {
    XQC_ENOBUF                          = 600,      // buf空间不足
    XQC_EVINTREAD                       = 601,      // 解析帧错误
    XQC_ENULLPTR                        = 602,      // 空指针，一般是申请内存失败
    XQC_EMALLOC                         = 603,      // 申请内存失败
    XQC_EILLPKT                         = 604,      // 非法报文
    XQC_ELEVEL                          = 605,      // 加密等级错误
    XQC_ECREATE_CONN                    = 606,      // 创建连接失败
    XQC_CLOSING                         = 607,      // 连接正在关闭，拒绝操作
    XQC_ECONN_NFOUND                    = 608,      // 找不到对应连接
    XQC_ESYS                            = 609,      // 系统错误，一般是公共库接口失败
    XQC_EAGAIN                          = 610,      // 写阻塞，类似EAGAIN
    XQC_EPARAM                          = 611,      // 参数错误
    XQC_ESTATE                          = 612,      // 连接状态异常
    XQC_ELIMIT                          = 613,      // 超过缓存限制
    XQC_EPROTO                          = 614,      // 违反协议规定
    XQC_ESOCKET                         = 615,      // socket接口失败
    XQC_EFATAL                          = 616,      // 致命错误，框架会立即destroy连接
    XQC_ESTREAM_ST                      = 617,      // 流状态异常
    XQC_ESEND_RETRY                     = 618,      // 发送retry失败
    XQC_ECONN_BLOCKED                   = 619,      // 连接级流控
    XQC_ESTREAM_BLOCKED                 = 620,      // 流级流控
    XQC_EENCRYPT                        = 621,      // 加密失败
    XQC_EDECRYPT                        = 622,      // 解密失败
    XQC_ESTREAM_NFOUND                  = 623,      // 找不到对应流
    XQC_EWRITE_PKT                      = 624,      // 创建包或写包头失败
    XQC_ECREATE_STREAM                  = 625,      // 创建流失败
    XQC_ESTREAM_RESET                   = 626,      // 流已被reset
    XQC_EDUP_FRAME                      = 627,      // 重复的帧
    XQC_EFINAL_SIZE                     = 628,      // STREAM帧final size错误

    XQC_E_MAX,
} xqc_transport_error_t;

#define TRANS_ERR_START 600
static const int TRANS_ERR_CNT = XQC_E_MAX - TRANS_ERR_START;


/* xquic TLS internal error codes: 7xx */
typedef enum {
    XQC_ERR_INVALID_ARGUMENT            = 700,
    XQC_ERR_UNKNOWN_PKT_TYPE            = 701,
    XQC_ERR_NOBUF                       = 702,
    XQC_ERR_PROTO                       = 703,
    XQC_ERR_INVALID_STATE               = 704,
    XQC_ERR_ACK_FRAME                   = 705,
    XQC_ERR_STREAM_ID_BLOCKED           = 706,
    XQC_ERR_STREAM_IN_USE               = 707,
    XQC_ERR_STREAM_DATA_BLOCKED         = 708,
    XQC_ERR_FLOW_CONTROL                = 709,
    XQC_ERR_STREAM_LIMIT                = 710,
    XQC_ERR_FINAL_OFFSET                = 711,
    XQC_ERR_CRYPTO                      = 712,
    XQC_ERR_PKT_NUM_EXHAUSTED           = 713,
    XQC_ERR_REQUIRED_TRANSPORT_PARAM    = 714,
    XQC_ERR_MALFORMED_TRANSPORT_PARAM   = 715,
    XQC_ERR_FRAME_ENCODING              = 716,
    XQC_ERR_TLS_DECRYPT                 = 717,
    XQC_ERR_STREAM_SHUT_WR              = 718,
    XQC_ERR_STREAM_NOT_FOUND            = 719,
    XQC_ERR_VERSION_NEGOTIATION         = 720,
    XQC_ERR_STREAM_STATE                = 721,
    XQC_ERR_NOKEY                       = 722,
    XQC_ERR_EARLY_DATA_REJECTED         = 723,
    XQC_ERR_RECV_VERSION_NEGOTIATION    = 724,
    XQC_ERR_CLOSING                     = 725,
    XQC_ERR_DRAINING                    = 726,
    XQC_ERR_TRANSPORT_PARAM             = 727,
    XQC_ERR_DISCARD_PKT                 = 728,
    XQC_ERR_FATAL                       = 729,
    XQC_ERR_NOMEM                       = 730,
    XQC_ERR_CALLBACK_FAILURE            = 731,
    XQC_ERR_INTERNAL                    = 732,
    XQC_EARLY_DATA_REJECT               = 733,
    XQC_TLS_CLIENT_INITIAL_ERROR        = 734,
    XQC_TLS_CLIENT_REINTIAL_ERROR       = 735,
    XQC_ENCRYPT_DATA_ERROR              = 736,
    XQC_DECRYPT_DATA_ERROR              = 737,

    XQC_TLS_ERR_MAX,
} xqc_tls_error_t;

#define TLS_ERR_START 700
static const int TLS_ERR_CNT = XQC_TLS_ERR_MAX - TLS_ERR_START;


/* xquic HTTP3/QPACK application error codes: 8xx */
typedef enum {
    /* HTTP/3 error codes */
    XQC_H3_EMALLOC                      = 800,  // 申请内存失败
    XQC_H3_ECREATE_STREAM               = 801,  // 创建流失败
    XQC_H3_ECREATE_REQUEST              = 802,  // 创建请求失败
    XQC_H3_EGOAWAY_RECVD                = 803,  // 接收到GOAWAY，拒绝操作
    XQC_H3_ECREATE_CONN                 = 804,  // 创建连接失败
    XQC_H3_EQPACK_ENCODE                = 805,  // QPACK编码失败
    XQC_H3_EQPACK_DECODE                = 806,  // QPACK解码失败
    XQC_H3_EPRI_TREE                    = 807,  // 优先级树失败
    XQC_H3_EPROC_CONTROL                = 808,  // 处理control流失败
    XQC_H3_EPROC_REQUEST                = 809,  // 处理request流失败
    XQC_H3_EPROC_PUSH                   = 810,  // 处理push流失败
    XQC_H3_EPARAM                       = 811,  // 参数错误
    XQC_H3_BUFFER_EXCEED                = 812,  // http send buffer 超过最大值
    XQC_H3_DECODE_ERROR                 = 813,  // 解码失败
    XQC_H3_INVALID_STREAM               = 814,  // stream非法，如多个control stream等
    XQC_H3_CLOSE_CRITICAL_STREAM        = 815,  // 非法关闭control stream、qpack encoder/decoder stream
    XQC_H3_STATE_ERROR                  = 816,  // http3 解码状态出错
    XQC_H3_CONTROL_ERROR                = 817,  // control stream error, such as setting not send first or send twice
    XQC_H3_CONTROL_DECODE_ERROR         = 818,  // control stream 解码错误，如遇到无法识别的frame type
    XQC_H3_CONTROL_DECODE_INVALID       = 819,  // control stream decoder invalid, 例如剩余长度非法
    XQC_H3_PRIORITY_ERROR               = 820,  // 优先级相关错误
    XQC_H3_INVALID_FRAME_TYPE           = 821,	
    XQC_H3_UNSUPPORT_FRAME_TYPE         = 822,
    XQC_H3_INVALID_HEADER   		= 823,  // 头部字段非法，如长度超过限制等
    XQC_H3_SETTING_ERROR    		= 824,  // SETTING相关错误

    XQC_H3_ERR_MAX,
} xqc_h3_error_t;

#define H3_ERR_START 800
static const int H3_ERR_CNT = XQC_H3_ERR_MAX - H3_ERR_START;


typedef enum {
    /* QPACK error codes */
    XQC_QPACK_DECODER_VARINT_ERROR      = 900,  // qpack 解码变长整数失败
    XQC_QPACK_ENCODER_ERROR             = 901,  // qpack编码过程中出错
    XQC_QPACK_DECODER_ERROR             = 902,  // qpack解码过程中出错
    XQC_QPACK_DYNAMIC_TABLE_ERROR       = 903,  // qpack动态表错误
    XQC_QPACK_STATIC_TABLE_ERROR        = 904,  // qpack静态表相关错误
    XQC_QPACK_SET_DTABLE_CAP_ERROR      = 905,  // qpack设置动态表容量出错
    XQC_QPACK_SEND_ERROR                = 906,  // qpack 发送数据或者控制报文出错
    XQC_QPACK_SAVE_HEADERS_ERROR        = 907,  // qpack 保存name-value到header结构体中时出错

    XQC_QPACK_ERR_MAX,
} xqc_qpack_error_t;

#define QPACK_ERR_START 900
static const int QPACK_ERR_CNT = XQC_QPACK_ERR_MAX - QPACK_ERR_START;


/**
 * convert a xquic error code to QUIC protocol error code, 
 * can be used before call XQC_CONN_ERR.
 * convertion happens mainly after receive and process packets or transport parameters
 * @param xqc_err xquic error code from internal module
 * @return if xqc_err got a mapping with a QUIC protocol error code, return QUIC protocol error code;
 *         if none, return xqc_err itself.
 */
int xqc_err_code_xquic_2_quic(int xqc_err);


#endif /* _XQC_ERRNO_H_INCLUDED_ */
