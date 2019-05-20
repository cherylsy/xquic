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
    )


  set(test_TLS
    tls_client.c
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


  add_executable(run_tls
      ${test_TLS}
  )
  target_include_directories(run_tls PRIVATE ${CUNIT_INCLUDE_DIRS})
  target_link_libraries(run_tls
    xquic
    ${CUNIT_LIBRARIES}
  )
  add_test(run_tls run_tls)
  add_dependencies(check run_tls)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl )
  include_directories(../transport/crypto/)


endif()
