
#ifndef XQC_MULTIPATH_H
#define XQC_MULTIPATH_H

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/common/xqc_common.h"
#include "xqc_packet.h"
#include "xqc_recv_record.h"


#define XQC_MP_NEW_PATH_MAX_TRY_COUNT   3

#define XQC_MP_FIRST_DATA_OFFSET        1460
#define XQC_MP_FIRST_FRAME_OFFSET       128 * 1024 // 128k

#define XQC_MP_INITIAL_PATH_ID          0

#define XQC_MP_PKT_REINJECTED(po) (po->po_flag & (XQC_POF_REINJECTED_ORIGIN | XQC_POF_REINJECTED_REPLICA))

/* types & structs */
typedef enum {
    XQC_MP_STATE_INIT       = 0,    /* initial state */
    XQC_MP_STATE_CREATED    = 1,    /* new path created, but unacked by peer */
    XQC_MP_STATE_ACTIVE     = 2,    /* path acked by peer, active state */
    XQC_MP_STATE_CLOSED     = 3,
} xqc_mp_path_state_t;

typedef enum {
    XQC_MP_STATE_ABANDON    = 0,    
    XQC_MP_STATE_STANDBY    = 1,    
    XQC_MP_STATE_AVAILABLE  = 2,    
} xqc_path_status_e;


/* path close mode: passive & proactive */
typedef enum {
    XQC_MP_PATH_CLOSE_PASSIVE = 0,
    XQC_MP_PATH_CLOSE_PROACTIVE = 1,
} xqc_path_close_mode_t;

typedef enum {
    XQC_MP_SCHED_DEFAULT = 0,
    XQC_MP_SCHED_IGNORE_CONG_CTRL = 1,
    XQC_MP_SCHED_REINJECTION = 1<<1,
} xqc_mp_sched_flag_t;

typedef uint32_t xqc_mp_sched_mode_t;

typedef enum {
    XQC_MP_PKT_PRIO_LOW = 0,
    XQC_MP_PKT_PRIO_DEFAULT = 1,
    XQC_MP_PKT_PRIO_HIGH = 2,
} xqc_mp_pkt_prioirty_t;


typedef struct xqc_path_metrics_s {

    uint32_t            path_request_send_count;
    uint32_t            path_request_recv_count;
    uint32_t            client_create_path_try_count;

} xqc_path_metrics_t;

/* path context */
struct xqc_path_ctx_s {

    /* Path_identifier */
    uint64_t            path_id;    /* path identifier */
    xqc_cid_t           path_scid;
    xqc_cid_t           path_dcid;

    /* Path_address: 4-tuple */
    unsigned char       peer_addr[sizeof(struct sockaddr_in6)],
                        local_addr[sizeof(struct sockaddr_in6)];
    socklen_t           peer_addrlen,
                        local_addrlen;

    char                addr_str[2*(XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];
    socklen_t           addr_str_len;

    /* Path_state */
    xqc_mp_path_state_t path_state;

    xqc_path_status_e   path_status;
    uint64_t            path_status_seq_number;
    uint64_t            path_prio;

    /* Path cc & ack tracking */
    xqc_send_ctl_t     *path_send_ctl;
    xqc_recv_record_t   path_recv_record[XQC_PNS_N]; /* record received pkt number range in a list */
    uint32_t            path_ack_eliciting_pkt[XQC_PNS_N]; /* Ack-eliciting Packets received since last ack sent */

    /* related structs */
    xqc_connection_t   *parent_conn;
    xqc_list_head_t     path_list;

    /* Path_metrics */
    xqc_path_metrics_t  path_metrics;
};


/* check mp support */
uint64_t xqc_conn_enable_multipath(xqc_connection_t *conn);

/* path create & close */
xqc_int_t xqc_conn_create_path(xqc_engine_t *engine, 
    xqc_cid_t *scid, uint64_t *new_path_id);
void xqc_conn_destroy_path(xqc_connection_t *conn);
xqc_path_ctx_t *xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id);


/* path status manage */
void xqc_path_update_status(xqc_path_ctx_t *path, 
    uint64_t path_status_seq, uint64_t path_status, uint64_t path_prio);


void xqc_mp_server_try_activate_path(xqc_connection_t *conn, uint64_t path_id, 
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen);

void xqc_mp_client_activate_path(xqc_path_ctx_t *path);


/* path statistics */
xqc_int_t xqc_mp_conn_active_path_count(xqc_connection_t *conn);
void xqc_mp_conn_stat_print(xqc_connection_t *conn, xqc_conn_stats_t *stats);
void xqc_mp_request_stat_print(xqc_connection_t *conn, 
    xqc_stream_t *stream, xqc_request_stats_t *stats);
void xqc_mp_path_stats_print(xqc_connection_t *conn, char *buff, unsigned buff_size);
void xqc_mp_request_path_stats_print(xqc_connection_t *conn, 
    xqc_stream_t *stream, char *buff, unsigned buff_size);

void xqc_mp_path_stats_to_stream_on_send(xqc_connection_t *conn, xqc_packet_out_t *po);
void xqc_mp_path_stats_to_stream_on_recv(xqc_connection_t *conn, 
    xqc_stream_t *stream, xqc_packet_in_t *packet_in);


/* path scheduler & send ctl */
xqc_path_ctx_t* xqc_mp_schedule_a_path(xqc_connection_t *conn, 
    xqc_packet_out_t *po, xqc_mp_sched_mode_t mode);

xqc_path_ctx_t* xqc_mp_schedule_paths_for_burst_sending(xqc_connection_t *conn, 
    xqc_list_head_t * po_head, int congest);
void xqc_mp_server_send_packets(xqc_connection_t *conn);
void xqc_mp_path_send_ctl_timer_expire(xqc_connection_t *conn, xqc_msec_t now);

xqc_int_t xqc_mp_should_reinject(xqc_connection_t *conn, xqc_send_ctl_t *real_ctl);
void xqc_mp_try_reinject_one_packet(xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out, xqc_mp_pkt_prioirty_t prio);

void xqc_mp_reset_request_stats(xqc_connection_t *conn);
void xqc_mp_check_app_limited(xqc_connection_t *conn);
xqc_msec_t xqc_mp_get_min_srtt_for_fc(xqc_connection_t *conn);


#endif /* XQC_MULTIPATH_H */


