
#include "src/crypto/xqc_tls_public.h"
#include "src/crypto/xqc_crypto.h"
#include "src/transport/xqc_conn.h"



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

    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
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

    } else {
        if (level == ssl_encryption_early_data) {
            if (read_secret) {
                xqc_hex_dump(conn->secret_hex[CLIENT_EARLY_TRAFFIC_SECRET], read_secret, secretlen);
            }

        } else if (level == ssl_encryption_handshake) {
            if (read_secret) {
                xqc_hex_dump(conn->secret_hex[CLIENT_HANDSHAKE_TRAFFIC_SECRET], read_secret, secretlen);
            }
            if (write_secret) {
                xqc_hex_dump(conn->secret_hex[SERVER_HANDSHAKE_TRAFFIC_SECRET], write_secret, secretlen);
            }

        } else if (level == ssl_encryption_application) {
            if (read_secret) {
                xqc_hex_dump(conn->secret_hex[CLIENT_TRAFFIC_SECRET_0], read_secret, secretlen);
            }
            if (write_secret) {
                xqc_hex_dump(conn->secret_hex[SERVER_TRAFFIC_SECRET_0], write_secret, secretlen);
            }
        }
    }
}
#endif

