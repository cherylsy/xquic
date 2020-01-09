cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -std=gnu11 -Werror -D DEBUG_PRINT -DNPRINT_MALLOC")

configure_file (
    xqc_cmake_config.h.in
    xqc_cmake_config.h
)

include(CMakeOptions.txt)

include_directories(
    "${CMAKE_CURRENT_BINARY_DIR}"
)

set(
    HTTP3_SOURCES

    http3/xqc_h3_conn.c
    http3/xqc_h3_stream.c
    http3/xqc_h3_request.c
    http3/xqc_h3_frame.c
    http3/xqc_h3_tnode.c
    http3/xqc_h3_qpack.c
    http3/xqc_h3_ringbuf.c
    http3/xqc_h3_qpack_token.c
    http3/xqc_h3_huffman_data.c
    http3/xqc_h3_qpack_huffman.c
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
    transport/xqc_recv_record.c
    transport/xqc_wakeup_pq.c
    transport/xqc_pacing.c
    transport/xqc_utils.c

    transport/crypto/xqc_tls_init.c
    transport/crypto/xqc_crypto.c
    transport/crypto/xqc_tls_cb.c
    transport/crypto/xqc_tls_0rtt.c
    transport/crypto/xqc_tls_if.c
    )

set(
    COMMON_SOURCES

    common/xqc_random.c
    common/xqc_variable_len_int.c
    common/xqc_str.c
    common/xqc_log.c
)

set(
    CONGESTION_CONTROL_SOURCES

    congestion_control/xqc_new_reno.c
    congestion_control/xqc_cubic.c
    congestion_control/xqc_bbr.c
    congestion_control/xqc_window_filter.c
    congestion_control/xqc_sample.c
)

add_library(
    xquic

    STATIC
    #SHARED


    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive"
        ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm64/lib/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm64/lib/libcrypto.a
        "-Wl,--no-whole-archive"
    )
    #link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.so.3)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.so.3)
else()
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive"
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.a
        "-Wl,--no-whole-archive"
        -lpthread
    )
endif()

# Strip binary for release builds
if (CMAKE_BUILD_TYPE STREQUAL Release)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} libxquic.so)
endif ()

##### for unit test #########
find_package(CUnit 2.1)
enable_testing()
set(HAVE_CUNIT ${CUNIT_FOUND})
if(HAVE_CUNIT)
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

add_subdirectory(tests)

add_executable(test_server tests/test_server.c)
add_executable(test_client tests/test_client.c)
add_executable(test_qpack_server tests/test_qpack_server.c)
add_executable(test_qpack_client tests/test_qpack_client.c)
#add_executable(xquic_client tests/axp/xquic_client.c tests/axp/axquic.c)
#add_executable(xquic_server tests/axp/xquic_server.c tests/axp/axquic.c)
#add_executable(test        tests/main.c)

include_directories( /usr/local/include )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/include/ )
include_directories(./transport/crypto/)
include_directories(${CMAKE_SOURCE_DIR}/)
link_directories( /usr/local/lib )
link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl) 

target_link_libraries(test_server xquic -levent -lm)
target_link_libraries(test_client xquic -levent -lm)
target_link_libraries(test_qpack_client xquic -levent -lm)
target_link_libraries(test_qpack_server xquic -levent -lm)
#target_link_libraries(xquic_client xquic -levent -lm)
#target_link_libraries(xquic_server xquic -levent -lm)
#target_link_libraries(test xquic -lssl )
#target_link_libraries(test xquic -lcrypto)


