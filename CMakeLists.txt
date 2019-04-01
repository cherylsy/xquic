cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -std=gnu11")

configure_file (
    xqc_cmake_config.h.in
    xqc_cmake_config.h
)

include(CMakeOptions.txt)

include_directories(
    "${CMAKE_CURRENT_BINARY_DIR}"
)

set(
    TRANSPORT_SOURCES

    transport/xqc_engine.c
    transport/xqc_conn.c
    transport/xqc_client.c
    transport/xqc_cid.c
    transport/xqc_packet_parser.c
    transport/xqc_frame_parser.c
    transport/xqc_stream.c
    transport/xqc_packet_out.c
    transport/xqc_packet_in.c
    transport/xqc_send_ctl.c
    transport/xqc_packet.c
    transport/xqc_frame.c
)

set(
    COMMON_SOURCES

    common/xqc_random.c
    common/xqc_variable_len_int.c
)

add_library(
    xquic

    STATIC

    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
)

##### for unit test #########
find_package(CUnit 2.1)
enable_testing()
set(HAVE_CUNIT ${CUNIT_FOUND})
if(HAVE_CUNIT)
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

add_subdirectory(tests)

add_executable(test_server tests/test_server.c)
#add_executable(test_client tests/test_client.c)

include_directories( /usr/local/include )
link_directories( /usr/local/lib )

target_link_libraries(test_server xquic)
#target_link_libraries(test_client xquic -levent)
