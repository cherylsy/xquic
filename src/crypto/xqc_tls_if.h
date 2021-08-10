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
 * @brief `xqc_tls_client_initial_pt` is called when client generates initial
 *
 * @param[in] conn  Connection context
 *
 * @retval XQC_OK means succeeds. <0 means error occurred 
 */
typedef int (*xqc_tls_client_initial_pt)(xqc_connection_t *conn);


/**
 * @brief `xqc_tls_recv_initial_pt` is called when server receives Initial packet. 
 *        Just used by server. Server can derive initial keys(packet protection & IV) in this fuction.
 *
 * @param[in] conn  Connection context
 * @param[in] dcid  The Destination Connection ID which is generated randomly by client.
 *
 * @retval XQC_OK means succeeds. <0 means error occurred 
 */
typedef xqc_int_t (*xqc_tls_recv_initial_pt)(xqc_connection_t *conn, xqc_cid_t *dcid);


/**
 * @brief `xqc_tls_recv_crypto_data_pt` is called when crypto data are received in crypto streams.
 *         Implementations should deliver the recvd data to TLS stack.
 *
 * @param[in] conn          Connection context
 * @param[in] data_pos      Buffer position of the received data
 * @param[in] data_len      Length of the received data
 * @param[in] encrypt_level Encryption level of the 
 *
 * @retval XQC_OK means succeeds. <0 means error occurred 
 */
typedef xqc_int_t (*xqc_tls_recv_crypto_data_pt)(xqc_connection_t *conn,
    const unsigned char *data_pos, size_t data_len, xqc_encrypt_level_t encrypt_level);


/**
 * @brief `xqc_handshake_completed` is called when tls handshake is completed
 *
 * @param[in] conn          Connection context
 * @param[in] user_data     User data for connection
 *
 * @retval XQC_OK means succeeds. <0 means error occurred 
 */
typedef int (*xqc_handshake_completed)(xqc_connection_t *conn, void *user_data);


/**
 * @brief `xqc_encrypt_pt` is used to define fuctions for encryption
 *
 * @param[in] conn          Connection context
 * @param[in] dest          Destination buffer position for encryption
 * @param[in] dest_len      Length of destination buffer
 * @param[in] plaintext     Plaintext buffer position
 * @param[in] plaintext_len Length of Plaintext buffer
 * @param[in] key           Key buffer position
 * @param[in] key_len       Length of key
 * @param[in] nonce         Nonce for encryption
 * @param[in] nonce_len     Length of nonce
 * @param[in] ad            Addition Data for AEAD encryption
 * @param[in] ad_len        Length of Addition Data
 *
 * @retval Length of the encrypted data. <0 means error occurred 
 */
typedef ssize_t (*xqc_encrypt_pt)(xqc_connection_t *conn, 
    uint8_t *dest, size_t dest_len, 
    const uint8_t *plaintext, size_t plaintext_len, 
    const uint8_t *key, size_t key_len, 
    const uint8_t *nonce, size_t nonce_len, 
    const uint8_t *ad, size_t ad_len, 
    void *user_data, xqc_aead_crypter_t * aead_crypter);

/**
 * @brief `xqc_decrypt_pt` is used to define fuctions for decryption
 *
 * @param[in] conn          Connection context
 * @param[in] dest          Destination buffer position for decryption
 * @param[in] dest_len      Length of destination buffer
 * @param[in] plaintext     Ciphertext buffer position
 * @param[in] plaintext_len Length of Ciphertext buffer
 * @param[in] key           Key buffer position
 * @param[in] key_len       Length of key
 * @param[in] nonce         Nonce for encryption
 * @param[in] nonce_len     Length of nonce
 * @param[in] ad            Addition Data for AEAD encryption
 * @param[in] ad_len        Length of Addition Data
 *
 * @retval Length of the decrypted data. <0 means error occurred 
 */
typedef ssize_t (*xqc_decrypt_pt)(xqc_connection_t *conn, 
    uint8_t *dest, size_t dest_len, 
    const uint8_t *ciphertext, size_t ciphertext_len, 
    const uint8_t *key, size_t key_len, 
    const uint8_t *nonce, size_t nonce_len, 
    const uint8_t *ad, size_t ad_len, 
    void *user_data, xqc_aead_crypter_t * aead_crypter);


/**
 * @brief `xqc_hp_mask_pt` is used to calculate hp mask
 *
 * @param[in] conn          Connection context
 * @param[in] dest          Destination buffer position for decryption
 * @param[in] dest_len      Length of destination buffer
 * @param[in] key           Key buffer position
 * @param[in] key_len       Length of key
 * @param[in] sample        Sample
 * @param[in] sample_len    Length of Sample
 *
 * @retval Length of the calculated hp mask. <0 means error occurred 
 */
typedef ssize_t (*xqc_hp_mask_pt)(xqc_connection_t *conn, 
    uint8_t *dest, size_t dest_len, 
    const uint8_t *key, size_t key_len, 
    const uint8_t *sample, size_t sample_len, 
    void *user_data, xqc_crypter_t * crypter);

/**
 * @brief `xqc_recv_retry` is called when transport recv retry packet
 *
 * @param[in] conn          Connection context
 * @param[in] user_data     User data for connection
 *
 * @retval XQC_OK means succeeds. <0 means error occurred 
 */
typedef int (*xqc_recv_retry)(xqc_connection_t *conn,
                                 xqc_cid_t * dcid);


void xqc_set_ssl_quic_method(SSL *ssl);

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
