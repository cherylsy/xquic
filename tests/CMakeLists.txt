
set(
  test_SOURCES
  main.c
  xqc_random_test.c
  xqc_timer_test.c
  xqc_pq_test.c
  xqc_common_test.c
  xqc_conn_test.c
  xqc_engine_test.c
  xqc_common_test.c
  xqc_vint_test.c
  xqc_packet_test.c
  xqc_recv_record_test.c
  xqc_reno_test.c
  xqc_cubic_test.c
  xqc_stream_frame_test.c
  xqc_wakeup_pq_test.c
  xqc_process_frame_test.c
)

set(
  test_TLS_C
  test_tls_client.c
  xqc_random_test.c
  xqc_timer_test.c
  xqc_pq_test.c
  xqc_common_test.c
  xqc_conn_test.c
  xqc_engine_test.c
  xqc_common_test.c
  xqc_vint_test.c
  xqc_packet_test.c
  xqc_tls_init_test.c
  xqc_tls_cb_test.c
)

set(test_TLS_S
  test_tls_server.c
  xqc_random_test.c
  xqc_timer_test.c
  xqc_pq_test.c
  xqc_common_test.c
  xqc_conn_test.c
  xqc_engine_test.c
  xqc_common_test.c
  xqc_vint_test.c
  xqc_packet_test.c
  xqc_tls_init_test.c
  xqc_tls_cb_test.c
)

set(test_TLS_0RTT
  test_tls_0rtt.c
  xqc_random_test.c
  xqc_timer_test.c
  xqc_pq_test.c
  xqc_common_test.c
  xqc_conn_test.c
  xqc_engine_test.c
  xqc_common_test.c
  xqc_vint_test.c
  xqc_packet_test.c
  xqc_tls_init_test.c
  xqc_tls_cb_test.c
)

set(test_TLS_REKEY
    test_tls_rekey.c
  xqc_random_test.c
  xqc_timer_test.c
  xqc_pq_test.c
  xqc_common_test.c
  xqc_conn_test.c
  xqc_engine_test.c
  xqc_common_test.c
  xqc_vint_test.c
  xqc_packet_test.c
  xqc_tls_init_test.c
  xqc_tls_cb_test.c
)

include_directories(${CMAKE_SOURCE_DIR}/libs/openssl/include/ )

add_executable(run_xqc_tests
  ${test_SOURCES}
)

target_link_libraries(run_xqc_tests
  xquic
  m
  ${CUNIT_LIBRARIES}
)

add_test(run_tests run_xqc_tests)

