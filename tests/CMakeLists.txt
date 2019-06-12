if(HAVE_CUNIT)
  include_directories(
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/lib/includes"
    "${CMAKE_BINARY_DIR}/lib/includes"
    "${CMAKE_SOURCE_DIR}/libs/openssl/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
  )

  set(test_SOURCES
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
    xqc_tls_init_test.c
    xqc_tls_cb_test.c
    xqc_recv_record_test.c
    xqc_reno_test.c
    xqc_stream_frame_test.c
    xqc_wakeup_pq_test.c
  )


  set(test_TLS_C
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



  add_executable(run_tests
    ${test_SOURCES}
  )
  target_include_directories(run_tests PRIVATE ${CUNIT_INCLUDE_DIRS})
  target_link_libraries(run_tests
    xquic
    ${CUNIT_LIBRARIES}
  )
  add_test(run_tests run_tests)
  add_dependencies(check run_tests)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/include/ )
  include_directories(../transport/crypto/)


  add_executable(test_tls_client
      ${test_TLS_C}
  )
  target_include_directories(test_tls_client PRIVATE ${CUNIT_INCLUDE_DIRS})
  target_link_libraries(test_tls_client
    xquic
    ${CUNIT_LIBRARIES}
  )
  add_test(test_tls_client test_tls_client)
  add_dependencies(check test_tls_client)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl )
  include_directories(../transport/crypto/)

  add_executable(test_tls_server
      ${test_TLS_S}
  )
  target_include_directories(test_tls_server PRIVATE ${CUNIT_INCLUDE_DIRS})
  target_link_libraries(test_tls_server
    xquic
    ${CUNIT_LIBRARIES}
  )
  add_test(test_tls_server test_tls_server)
  add_dependencies(check test_tls_server)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl )
  include_directories(../transport/crypto/)


  add_executable(test_tls_0rtt
      ${test_TLS_0RTT}
  )
  target_include_directories(test_tls_0rtt PRIVATE ${CUNIT_INCLUDE_DIRS})
  target_link_libraries(test_tls_0rtt
    xquic
    ${CUNIT_LIBRARIES}
  )
  add_test(test_tls_0rtt test_tls_0rtt)
  add_dependencies(check test_tls_0rtt)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl )
  include_directories(../transport/crypto/)



endif()
