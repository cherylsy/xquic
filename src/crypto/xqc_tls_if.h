#ifndef _XQC_TLS_IF_INCLUDED_
#define _XQC_TLS_IF_INCLUDED_

#include <openssl/ssl.h>
#include <assert.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/common/xqc_str.h"
#include "src/common/xqc_list.h"
#include "src/transport/xqc_frame.h"
#include "src/crypto/xqc_digist.h"
#include "src/crypto/xqc_crypto.h"
#include "src/transport/xqc_packet.h"


typedef struct xqc_ssl_session_ticket_key_s{
    size_t                      size;
    uint8_t                     name[16];
    uint8_t                     hmac_key[32];
    uint8_t                     aes_key[32];
} xqc_ssl_session_ticket_key_t;


typedef struct {
    const uint8_t *stateless_reset_token;
    const uint8_t *rand;
    size_t randlen;
} xqc_pkt_stateless_reset;


#define XQC_HP_TX   (0)
#define XQC_HP_RX   (1)
#define XQC_HP_MAX_DIRECTION (2)

#define XQC_EARLY_DATA_CONTEXT          "xquic"
#define XQC_EARLY_DATA_CONTEXT_LEN      (sizeof(XQC_EARLY_DATA_CONTEXT) - 1)

struct xqc_tls_context
{
    //aead suites
    xqc_aead_t          aead;
    /** 
     * crypto suites (without addition info) 
     * */
    xqc_crypto_t        crypto;
    //digist suites 
    xqc_digist_t        prf;
    xqc_aead_crypter_t *aead_encrypter;
    xqc_aead_crypter_t *aead_decrypter;
    xqc_crypter_t      *hp[XQC_HP_MAX_DIRECTION];
};

typedef struct xqc_tls_context xqc_tls_context_t;


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
 * :enum:`XQC_TLS_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * XQC_TLS_CRYPTO.
 */
typedef int (*xqc_client_initial)(xqc_connection_t *conn);

/**
 * @brief `xqc_tls_recv_initial_pt` is called when server receives Initial packet. 
 *        Just used by server. Server can derive initial keys(packet protection & IV) in this fuction.
 * @param dcid the Destination Connection ID which is generated randomly by client.
 * @param data_len length of the received data
 *
 * @return XQC_OK means succeeds. <0 means error occurred calling TLS functions
 */
typedef xqc_int_t (*xqc_tls_recv_initial_pt)(xqc_connection_t *conn, xqc_cid_t *dcid);


/**
 * @brief `xqc_tls_recv_crypto_data_pt` is called when crypto data are received in crypto streams.
 *         implementations should deliver the recvd data to TLS stack.
 * @param data_pos buffer position of the received data
 * @param data_len length of the received data
 *
 * @return XQC_OK means succeeds. <0 means error occurred calling TLS functions
 */
typedef xqc_int_t (*xqc_tls_recv_crypto_data_pt)(xqc_connection_t *conn,
    const unsigned char *data_pos, size_t data_len, xqc_encrypt_level_t encrypt_level);


/**
 * @functypedef
 *
 * :type:`xqc_handshake_completed` is invoked when QUIC
 * cryptographic handshake has completed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`XQC_TLS_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_handshake_completed)(xqc_connection_t *conn, void *user_data);


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
 * |dest|, or :enum:`XQC_TLS_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef ssize_t (*xqc_encrypt_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * aead_crypter);

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
 * :enum:`XQC_TLS_DECRYPT`.  For any other errors, return
 * :enum:`XQC_TLS_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef ssize_t (*xqc_decrypt_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * aead_crypter);


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
 * |dest|, or :enum:`XQC_TLS_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef ssize_t (*xqc_hp_mask_t)(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *sample,
                                  size_t samplelen, void *user_data, xqc_crypter_t * crypter);



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
 * :enum:`XQC_TLS_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_recv_retry)(xqc_connection_t *conn,
                                 xqc_cid_t * dcid);


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
 * :enum:`XQC_TLS_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*xqc_update_key_t)(xqc_connection_t *conn, void *user_data);



int xqc_client_initial_cb(xqc_connection_t *conn);
xqc_int_t xqc_tls_recv_initial_cb(xqc_connection_t * conn, xqc_cid_t *dcid);

xqc_int_t xqc_tls_recv_crypto_data_cb(xqc_connection_t *conn,
    const unsigned char *data_pos, size_t data_len, xqc_encrypt_level_t level);
int xqc_handshake_completed_cb(xqc_connection_t *conn, void *user_data);


int xqc_tls_recv_retry_cb(xqc_connection_t * conn,xqc_cid_t *dcid);

ssize_t xqc_do_hs_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * crypter);

ssize_t xqc_do_hs_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * crypter);

ssize_t xqc_do_encrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * crypter);

ssize_t xqc_do_decrypt(xqc_connection_t *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data, xqc_aead_crypter_t * crypter);

ssize_t xqc_in_hp_mask_cb(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data, xqc_crypter_t * crypter);

ssize_t xqc_hp_mask_cb(xqc_connection_t *conn, uint8_t *dest, size_t destlen,
        const uint8_t *key, size_t keylen, const uint8_t *sample,
        size_t samplelen, void *user_data, xqc_crypter_t * crypter);

/* Return 0 means forced 1RTT mode, return -1 means early data reject, return 1 means early data accept */
int xqc_tls_is_early_data_accepted(xqc_connection_t * conn);
/* Include BORINGSSL and OPENSSL. return XQC_TRUE for early data accepted, XQC_FALSE for early data rejected */
int xqc_crypto_is_early_data_accepted(xqc_connection_t * conn);

int xqc_is_ready_to_send_early_data(xqc_connection_t * conn);

// create crypto nonce
void xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen,uint64_t pkt_num) ;
int xqc_conn_prepare_key_update(xqc_connection_t * conn);
int xqc_start_key_update(xqc_connection_t * conn);
int xqc_tls_check_tx_key_ready(xqc_connection_t * conn);
int xqc_tls_check_rx_key_ready(xqc_connection_t * conn);
int xqc_tls_check_hs_tx_key_ready(xqc_connection_t * conn);
int xqc_tls_check_hs_rx_key_ready(xqc_connection_t * conn);
int xqc_tls_check_0rtt_key_ready(xqc_connection_t * conn);
int xqc_tls_free_tlsref(xqc_connection_t * conn);
int xqc_tls_free_msg_cb_buffer(xqc_connection_t * conn);
int xqc_tls_free_engine_config(xqc_engine_ssl_config_t *ssl_config);


// configure  quic related write secret , Call from TLS Stack
int xqc_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret,
    size_t secretlen);

// configure  quic related write secret , Call from TLS Stack
int xqc_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret,
    size_t secretlen);

// convert xqc encrypt level to ssl encrypt level 
enum ssl_encryption_level_t  xqc_convert_xqc_to_ssl_level(xqc_encrypt_level_t level);

// convert ssl encrypt level to xqc encrypt level 
xqc_encrypt_level_t  xqc_convert_ssl_to_xqc_level(enum ssl_encryption_level_t level);

#endif
