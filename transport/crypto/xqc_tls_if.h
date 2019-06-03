#ifndef _XQC_TLS_IF_INCLUDED_
#define _XQC_TLS_IF_INCLUDED_

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <assert.h>
#include "xqc_crypto.h"
#include "include/xquic_typedef.h"
#include "common/xqc_str.h"
#include "common/xqc_list.h"
#include "transport/xqc_frame.h"


typedef struct {
    const uint8_t *stateless_reset_token;
    const uint8_t *rand;
    size_t randlen;
} xqc_pkt_stateless_reset;




/**
 * @functypedef
 *
 * :type:`xqc_client_initial` is invoked when client application
 * asks TLS stack to produce first TLS cryptographic handshake data.
 *
 * This implementation of this callback must get the first handshake
 * data from TLS stack and pass it to xqc library using
 * `xqc_conn_submit_crypto_data` function.  Make sure that before
 * calling `xqc_conn_submit_crypto_data` function, client
 * application must create initial packet protection keys and IVs, and
 * provide them to xqc library using
 * `xqc_conn_set_initial_tx_keys` and
 * `xqc_conn_set_initial_rx_keys`.
 *
 * This callback function must return 0 if it succeeds, or
 * :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * XQC_ERR_CRYPTO.
 */
typedef int (*xqc_client_initial)(xqc_connection_t *conn);

/**
 * @functypedef
 *
 * :type:`xqc_recv_client_initial` is invoked when server receives
 * Initial packet from client.  An server application must implement
 * this callback, and generate initial keys and IVs for both
 * transmission and reception.  Install them using
 * `xqc_conn_set_initial_tx_keys` and
 * `xqc_conn_set_initial_rx_keys.  |dcid| is the destination
 * connection ID which client generated randomly.  It is used to
 * derive initial packet protection keys.
 *
 * The callback function must return 0 if it succeeds.  If an error
 * occurs, return :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * XQC_ERR_CRYPTO.
 */
typedef int (*xqc_recv_client_initial)(xqc_connection_t *conn,
                                          xqc_cid_t *dcid,
                                          void *user_data);

/**
 * @functypedef
 *
 * :type`xqc_recv_crypto_data` is invoked when crypto data are
 * received.  The received data are pointed by |data|, and its length
 * is |datalen|.  The |offset| specifies the offset where |data| is
 * positioned.  |user_data| is the arbitrary pointer passed to
 * `xqc_conn_client_new` or `xqc_connection_t_server_new`.  The ngtcp2
 * library ensures that the crypto data is passed to the application
 * in the increasing order of |offset|.  |datalen| is always strictly
 * greater than 0.
 *
 * The application should provide the given data to TLS stack.
 *
 * The callback function must return 0 if it succeeds.  If TLS stack
 * reported error, return :enum:`XQC_ERR_CRYPTO`.  If application
 * encounters fatal error, return :enum:`XQC_ERR_CALLBACK_FAILURE`
 * which makes the library call return immediately.  If the other
 * value is returned, it is treated as
 * :enum:`XQC_ERR_CALLBACK_FAILURE`.
 */
typedef int (*xqc_recv_crypto_data)(xqc_connection_t *conn, uint64_t offset,
                                       const uint8_t *data, size_t datalen,
                                       void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_handshake_completed` is invoked when QUIC
 * cryptographic handshake has completed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_handshake_completed)(xqc_connection_t *conn, void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_recv_version_negotiation` is invoked when Version
 * Negotiation packet is received.  |hd| is the pointer to the QUIC
 * packet header object.  The vector |sv| of |nsv| elements contains
 * the QUIC version the server supports.  Since Version Negotiation is
 * only sent by server, this callback function is used by client only.
 *
 * The callback function must return 0 if it succeeds, or
 * :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef int (*xqc_recv_version_negotiation)(xqc_connection_t *conn,
                                               const xqc_pkt_hd *hd,
                                               const uint32_t *sv, size_t nsv,
                                               void *user_data);


/**
 * @functypedef
 *
 * :type:`xqc_encrypt` is invoked when the ngtcp2 library asks the
 * application to encrypt packet payload.  The packet payload to
 * encrypt is passed as |plaintext| of length |plaintextlen|.  The
 * encryption key is passed as |key| of length |keylen|.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must encrypt |plaintext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest| of length |destlen|.
 *
 * |dest| and |plaintext| may point to the same buffer.
 *
 * The callback function must return the number of bytes written to
 * |dest|, or :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef size_t (*xqc_encrypt_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_decrypt` is invoked when the ngtcp2 library asks the
 * application to decrypt packet payload.  The packet payload to
 * decrypt is passed as |ciphertext| of length |ciphertextlen|.  The
 * decryption key is passed as |key| of length |keylen|.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must decrypt |ciphertext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest| of length |destlen|.
 *
 * |dest| and |ciphertext| may point to the same buffer.
 *
 * The callback function must return the number of bytes written to
 * |dest|.  If TLS stack fails to decrypt data, return
 * :enum:`XQC_ERR_TLS_DECRYPT`.  For any other errors, return
 * :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef size_t (*xqc_decrypt_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);


/**
 * @functypedef
 *
 * :type:`xqc_hp_mask` is invoked when the ngtcp2 library asks the
 * application to produce mask to encrypt or decrypt packet header.
 * The key is passed as |key| of length |keylen|.  The sample is
 * passed as |sample| of length |samplelen|.
 *
 * The implementation of this callback must produce a mask using the
 * header protection cipher suite specified by QUIC specification and
 * write the result into the buffer pointed by |dest| of length
 * |destlen|.  The length of mask must be at least
 * :macro:`XQC_HP_MASKLEN`.  The library ensures that |destlen| is
 * at least :macro:`XQC_HP_MASKLEN`.
 *
 * The callback function must return the number of bytes written to
 * |dest|, or :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef size_t (*xqc_hp_mask_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *sample,
                                  size_t samplelen, void *user_data);


/**
 * @functypedef
 *
 * :type:`xqc_recv_stream_data` is invoked when stream data is
 * received.  The stream is specified by |stream_id|.  If |fin| is
 * nonzero, this portion of the data is the last data in this stream.
 * |offset| is the offset where this data begins.  The library ensures
 * that data is passed to the application in the non-decreasing order
 * of |offset|.  The data is passed as |data| of length |datalen|.
 * |datalen| may be 0 if and only if |fin| is nonzero.
 *
 * The callback function must return 0 if it succeeds, or
 * :enum:`XQC_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*xqc_recv_stream_data)(xqc_connection_t *conn, uint64_t stream_id,
                                       int fin, uint64_t offset,
                                       const uint8_t *data, size_t datalen,
                                       void *user_data, void *stream_user_data);


/**
 * @functypedef
 *
 * :type:`xqc_acked_crypto_offset` is a callback function which is
 * called when crypto stream data is acknowledged, and application can
 * free the data.  This works like
 * :type:`xqc_acked_stream_data_offset` but crypto stream has no
 * stream_id and stream_user_data, and |datalen| never become 0.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*xqc_acked_crypto_offset)(xqc_connection_t *conn, uint64_t offset,
                                          size_t datalen, void *user_data);



/**
 * @functypedef
 *
 * :type:`xqc_acked_stream_data_offset` is a callback function
 * which is called when stream data is acked, and application can free
 * the data.  The acked range of data is [offset, offset + datalen).
 * For a given stream_id, this callback is called sequentially in
 * increasing order of |offset|.  |datalen| is normally strictly
 * greater than 0.  One exception is that when a packet which includes
 * STREAM frame which has fin flag set, and 0 length data, this
 * callback is invoked with 0 passed as |datalen|.
 *
 * If a stream is closed prematurely and stream data is still
 * in-flight, this callback function is not called for those data.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*xqc_acked_stream_data_offset)(xqc_connection_t *conn,
                                               uint64_t stream_id,
                                               uint64_t offset, size_t datalen,
                                               void *user_data,
                                               void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`xqc_stream_open` is a callback function which is called
 * when remote stream is opened by peer.  This function is not called
 * if stream is opened by implicitly (we might reconsider this
 * behaviour).
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*xqc_stream_open)(xqc_connection_t *conn, uint64_t stream_id,
                                  void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_stream_close` is invoked when a stream is closed.
 * This callback is not called when QUIC connection is closed before
 * existing streams are closed.  |app_error_code| indicates the error
 * code of this closure.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*xqc_stream_close)(xqc_connection_t *conn, uint64_t stream_id,
                                   uint16_t app_error_code, void *user_data,
                                   void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`xqc_recv_stateless_reset` is a callback function which is
 * called when Stateless Reset packet is received.  The |hd| is the
 * packet header, and the stateless reset details are given in |sr|.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*xqc_recv_stateless_reset)(xqc_connection_t *conn,
                                           const xqc_pkt_hd *hd,
                                           const xqc_pkt_stateless_reset *sr,
                                           void *user_data);



/**
 * @functypedef
 *
 * :type:`xqc_recv_retry` is invoked when Retry packet is received.
 * This callback is client only.
 *
 * Application must regenerate packet protection key, IV, and header
 * protection key for Initial packets using the destination connection
 * ID obtained by `xqc_conn_get_dcid()` and install them by calling
 * `xqc_conn_install_initial_tx_keys()` and
 * `xqc_conn_install_initial_rx_keys()`.
 *
 * 0-RTT data accepted by the xqc library will be retransmitted by
 * the library automatically.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_recv_retry)(xqc_connection_t *conn, const xqc_pkt_hd *hd,
                                 void *retry,
                                 void *user_data);


/**
 * @functypedef
 *
 * :type:`xqc_extend_max_streams` is a callback function which is
 * called every time max stream ID is strictly extended.
 * |max_streams| is the cumulative number of streams which a local
 * endpoint can open.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_extend_max_streams)(xqc_connection_t *conn,
                                         uint64_t max_streams, void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_rand` is a callback function to get randomized byte
 * string from application.  Application must fill random |destlen|
 * bytes to the buffer pointed by |dest|.  |ctx| provides the context
 * how the provided random byte string is used.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_rand)(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
                           void * ctx, void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_get_new_connection_id` is a callback function to ask
 * an application for new connection ID.  Application must generate
 * new unused connection ID with the exact |cidlen| bytes and store it
 * in |cid|.  It also has to generate stateless reset token into
 * |token|.  The length of stateless reset token is
 * :macro:`xqc_STATELESS_RESET_TOKENLEN` and it is guaranteed that
 * the buffer pointed by |cid| has the sufficient space to store the
 * token.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_get_new_connection_id)(xqc_connection_t *conn, xqc_cid_t *cid,
                                            uint8_t *token, size_t cidlen,
                                            void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_remove_connection_id` is a callback function which
 * notifies the application that connection ID |cid| is no longer used
 * by remote endpoint.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_remove_connection_id)(xqc_connection_t *conn,
                                           const xqc_cid_t *cid,
                                           void *user_data);

/**
 * @functypedef
 *
 * :type:`xqc_update_key` is a callback function which tells the
 * application that it should update and install new keys.
 *
 * In the callback function, the application has to generate new keys
 * for both encryption and decryption, and install them to |conn|
 * using `xqc_conn_update_tx_key` and `ngtcp2_conn_update_rx_key`.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_update_key_t)(xqc_connection_t *conn, void *user_data);


/**
 * @functypedef
 *
 * :type:`ngtcp2_path_validation` is a callback function which tells
 * the application the outcome of path validation.  |path| is the path
 * to validate.  If |res| is
 * :enum:`NGTCP2_PATH_VALIDATION_RESULT_SUCCESS`, the path validation
 * succeeded.  If |res| is
 * :enum:`NGTCP2_PATH_VALIDATION_RESULT_FAILURE`, the path validation
 * failed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_path_validation)(xqc_connection_t *conn,
                                      void *path,
                                      void * res,
                                      void *user_data);




int xqc_client_initial_cb(xqc_connection_t *conn);
int xqc_recv_client_initial_cb(xqc_connection_t * conn,
         xqc_cid_t *dcid,
        void *user_data);

int xqc_recv_crypto_data_cb(xqc_connection_t *conn, uint64_t offset,
        const uint8_t *data, size_t datalen,
        void *user_data);
int xqc_handshake_completed_cb(xqc_connection_t *conn, void *user_data);

size_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

size_t xqc_do_hs_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

size_t xqc_do_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

size_t xqc_do_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

size_t do_in_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data);

size_t do_hp_mask(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data);

int xqc_conn_prepare_key_update(xqc_connection_t * conn);
int xqc_start_key_update(xqc_connection_t * conn);
#endif
