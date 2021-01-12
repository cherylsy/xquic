
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_crypto.h"
#include "src/transport/xqc_conn.h"



const char* xqc_crypto_initial_salt[] = {

    "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0",  /* draft-18 */
    "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02",  /* draft-27 */
    "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02",  /* draft-28 */
    "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99",  /* draft-29 */
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  /* placeholder */
};


#ifdef XQC_PRINT_SECRET
void
xqc_tls_print_secret(SSL *ssl, xqc_connection_t *conn, enum ssl_encryption_level_t level,
    const unsigned char *read_secret, const unsigned char *write_secret, size_t secretlen)
{
    if (strlen((const char*)conn->client_random_hex) == 0) {
        unsigned char client_random[33] = {0};
        size_t out_len = 32;
        out_len = SSL_get_client_random(ssl, client_random, out_len);
        xqc_hex_dump(conn->client_random_hex, client_random, out_len);
    }

    if (level == ssl_encryption_early_data) {
        if (write_secret) {
            xqc_hex_dump(conn->secret_hex[CLIENT_EARLY_TRAFFIC_SECRET], write_secret, secretlen);
        }

    } else if (level == ssl_encryption_handshake) {
        if (write_secret) {
            xqc_hex_dump(conn->secret_hex[CLIENT_HANDSHAKE_TRAFFIC_SECRET], write_secret, secretlen);
        }
        if (read_secret) {
            xqc_hex_dump(conn->secret_hex[SERVER_HANDSHAKE_TRAFFIC_SECRET], read_secret, secretlen);
        }

    } else if (level == ssl_encryption_application) {
        if (write_secret) {
            xqc_hex_dump(conn->secret_hex[CLIENT_TRAFFIC_SECRET_0], write_secret, secretlen);
        }
        if (read_secret) {
            xqc_hex_dump(conn->secret_hex[SERVER_TRAFFIC_SECRET_0], read_secret, secretlen);
        }
    }
}
#endif



