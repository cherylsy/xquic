if(HAVE_CUNIT)
  include_directories(
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/lib/includes"
    "${CMAKE_BINARY_DIR}/lib/includes"
    ${CUNIT_INCLUDE_DIRS}
  )

  set(test_SOURCES
    main.c
    xqc_random_test.c
    xqc_timer_test.c
    xqc_conn_test.c
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
endif()
