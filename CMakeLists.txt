cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC ")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -O0 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC ")

if(GCOV STREQUAL "on")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

if(ANDROID_ABI OR PLATFORM MATCHES "mac")
    if(PLATFORM STREQUAL "mac32")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    endif()
endif()

configure_file (
    xqc_configure.h.in
    xqc_configure.h
)

include(CMakeOptions.txt)

include_directories(
    include
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/include"
)


set(

    HTTP3_SOURCES

    "src/http3/xqc_h3_conn.c"
    "src/http3/xqc_h3_stream.c"
    "src/http3/xqc_h3_request.c"
    "src/http3/xqc_h3_frame.c"
    "src/http3/xqc_h3_tnode.c"
    "src/http3/xqc_h3_qpack.c"
    "src/http3/xqc_h3_ringbuf.c"
    "src/http3/xqc_h3_qpack_token.c"
    "src/http3/xqc_h3_huffman_data.c"
    "src/http3/xqc_h3_qpack_huffman.c"
)


set(

    TRANSPORT_SOURCES

    "src/transport/xqc_engine.c"
    "src/transport/xqc_conn.c"
    "src/transport/xqc_client.c"
    "src/transport/xqc_cid.c"
    "src/transport/xqc_packet_parser.c"
    "src/transport/xqc_frame_parser.c"
    "src/transport/xqc_stream.c"
    "src/transport/xqc_packet_out.c"
    "src/transport/xqc_packet_in.c"
    "src/transport/xqc_send_ctl.c"
    "src/transport/xqc_packet.c"
    "src/transport/xqc_frame.c"
    "src/transport/xqc_recv_record.c"
    "src/transport/xqc_wakeup_pq.c"
    "src/transport/xqc_pacing.c"
    "src/transport/xqc_utils.c"

    "src/crypto/xqc_tls_init.c"
    "src/crypto/xqc_tls_0rtt.c"
    "src/crypto/xqc_tls_if.c"
    "src/crypto/xqc_crypto_material.c"
    "src/crypto/xqc_tls_stack_cb.c"
    "src/crypto/xqc_hkdf.c"
    "src/crypto/xqc_transport_params.c"
    "src/crypto/xqc_crypto.c"
    "src/crypto/xqc_tls_cb.c"
    "src/crypto/openssl/xqc_hkdf.c"
    "src/crypto/openssl/xqc_crypto.c"
    "src/crypto/openssl/xqc_tls_if.c"

    )

set(
    COMMON_SOURCES

    "src/common/xqc_random.c"
    "src/common/xqc_variable_len_int.c"
    "src/common/xqc_str.c"
    "src/common/xqc_log.c"
)

set(
    CONGESTION_CONTROL_SOURCES

    "src/congestion_control/xqc_new_reno.c"
    "src/congestion_control/xqc_cubic.c"
    "src/congestion_control/xqc_bbr.c"
    "src/congestion_control/xqc_window_filter.c"
    "src/congestion_control/xqc_sample.c"
)

add_library(
    xquic

    #STATIC
    SHARED


    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)

add_library(
    xquic_openssl

    #STATIC
    SHARED
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)


if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_libraries(
       xquic
       "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/script/xquic.lds"
       ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm64/lib/libssl.a
       ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm64/lib/libcrypto.a
       "-Wl,--no-whole-archive"
    )
    #link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.so.3)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.so.3)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_link_libraries(
            xquic
            "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/script/xquic.lds"
            ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm/lib/libssl.a
            ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-arm/lib/libcrypto.a
            "-Wl,--no-whole-archive"
    )
    #link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.so.3)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.so.3)
elseif(ANDROID_ABI STREQUAL "x86")
    target_link_libraries(
            xquic
            "-ldl -Wl,--whole-archive"
            ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-x86/lib/libssl.a
            ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/android-x86/lib/libcrypto.a
            "-Wl,--no-whole-archive"
    )
    #link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.so.3)
    #link_libraries( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.so.3)
elseif(PLATFORM MATCHES "mac")
    target_link_libraries(
            xquic
            "-ldl -Wl,-all_load"
            ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.a
            ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.a
            "-Wl,-noall_load"
            -lpthread
    )
else()
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive"
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/libcrypto.a
        "-Wl,--no-whole-archive"
        -lpthread
    )

    target_link_libraries(
        xquic_openssl
        "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/script/xquic.lds"
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
add_executable(test_qpack_fuzzing tests/test_qpack_fuzzing.c)
add_executable(xquic_bench benchmark/xquic_bench.c)
#add_executable(xquic_client tests/axp/xquic_client.c tests/axp/axquic.c)
#add_executable(xquic_server tests/axp/xquic_server.c tests/axp/axquic.c)
#add_executable(test        tests/main.c)

include_directories( /usr/local/include )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/include/ )
include_directories(./transport/crypto/)
include_directories(${CMAKE_SOURCE_DIR}/)
link_directories( /usr/local/lib )
link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl) 

if(PLATFORM STREQUAL "mac32")
    target_link_libraries(test_server xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
    target_link_libraries(test_client xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
else()
    target_link_libraries(test_server xquic -levent -lm)
    target_link_libraries(test_client xquic -levent -lm)
endif()

target_link_libraries(test_qpack_client xquic -levent -lm)
target_link_libraries(test_qpack_server xquic -levent -lm)
target_link_libraries(test_qpack_fuzzing xquic -levent -lm)
target_link_libraries(xquic_bench xquic -levent -lm)

#target_link_libraries(xquic_client xquic -levent -lm)
#target_link_libraries(xquic_server xquic -levent -lm)
#target_link_libraries(test xquic -lssl )
#target_link_libraries(test xquic -lcrypto)


