
#include "xquic.h"
#include "xqc_transport.h"


int 
xqc_connect(xqc_client_connection_t *client_conn, xqc_engine_t *engine, void *user_data) 
{
    int ret = XQC_ERROR;
    xqc_cid_t dcid;
    xqc_cid_t scid;
    xqc_conn_callbacks_t callbacks;

    

    client_conn->xc = xqc_client_create_connection(engine, dcid, scid, 
                    callbacks, engine->settings, user_data);

    if (client_conn->xc == NULL) {
        /* TODO:LOG */
        goto fail;
    }

fail:
    ret = XQC_ERROR;
    return ret;
}

