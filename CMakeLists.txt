cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

if (NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if (NOT BABASSL_PATH)
set(BABASSL_PATH "/usr/local/babassl")
endif()

if(XQC_OPENSSL_IS_BORINGSSL)
    include_directories(third_party/boringssl/include)
endif()

if(XQC_PRINT_SECRET)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_PRINT_SECRET")
endif()

if (XQC_ONLY_ERROR_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ONLY_ERROR_LOG ")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC ")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -O0 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC -DXQC_DEBUG ")

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
    "src/transport/xqc_multipath.c"
)

set (
    CRYPTO_SOURCE

    "src/crypto/xqc_tls_init.c"
    "src/crypto/xqc_tls_0rtt.c"
    "src/crypto/xqc_tls_if.c"
    "src/crypto/xqc_crypto_material.c"
    "src/crypto/xqc_tls_stack_cb.c"
    "src/crypto/xqc_hkdf.c"
    "src/crypto/xqc_transport_params.c"
    "src/crypto/xqc_crypto.c"
    "src/crypto/xqc_tls_cb.c"
    "src/crypto/xqc_tls_public.c"
)

if(XQC_OPENSSL_IS_BORINGSSL)
set (
    CRYPTO_SOURCE

    ${CRYPTO_SOURCE}
    "src/crypto/boringssl/xqc_hkdf.c"
    "src/crypto/boringssl/xqc_crypto.c"
    "src/crypto/boringssl/xqc_tls_if.c"
)
else()
set(
    CRYPTO_SOURCE

    ${CRYPTO_SOURCE}
    "src/crypto/openssl/xqc_hkdf.c"
    "src/crypto/openssl/xqc_crypto.c"
    "src/crypto/openssl/xqc_tls_if.c"
)
endif()

set(
    COMMON_SOURCES

    "src/common/xqc_random.c"
    "src/common/xqc_variable_len_int.c"
    "src/common/xqc_str.c"
    "src/common/xqc_log.c"
)

set(
    CONGESTION_CONTROL_SOURCES

    "src/congestion_control/xqc_cubic.c"
    "src/congestion_control/xqc_cubic_kernel.c"
    "src/congestion_control/xqc_bbr.c"
    "src/congestion_control/xqc_window_filter.c"
    "src/congestion_control/xqc_sample.c"
)

if(XQC_DISABLE_RENO)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_DISABLE_RENO ")
else()
    set(
        CONGESTION_CONTROL_SOURCES

        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_new_reno.c"
    )
endif()

if(XQC_ENABLE_BBR2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_ENABLE_BBR2 ")
    set(
        CONGESTION_CONTROL_SOURCES

        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_bbr2.c"
    )
endif()

set (
    XQC_SOURCE 
    
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${CRYPTO_SOURCE}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)

add_library(
    xquic-static
    STATIC
    ${XQC_SOURCE}
)

add_library(
    xquic
    SHARED
    ${XQC_SOURCE}
)


if (XQC_ENABLE_TESTING)
    set(XQC_LDS_FILE "xquic_test.lds")
else()
    set(XQC_LDS_FILE "xquic.lds")
endif()

if(XQC_OPENSSL_IS_BORINGSSL)
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/scripts/${XQC_LDS_FILE}"
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl/build/ssl/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl/build/crypto/libcrypto.a
        "-Wl,--no-whole-archive"
        -lpthread
    )
elseif(PLATFORM MATCHES "mac")
    target_link_libraries(
        xquic
        "-ldl -Wl,-all_load"
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/BabaSSL/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/BabaSSL/libcrypto.a
        "-Wl,-noall_load"
        -lpthread
    )
else()
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/scripts/${XQC_LDS_FILE}"
        ${BABASSL_PATH}/lib/libssl.a
        ${BABASSL_PATH}/lib/libcrypto.a
        "-Wl,--no-whole-archive"
        -lpthread
    )
endif()

# Strip binary for release builds
if (CMAKE_BUILD_TYPE STREQUAL MinSizeRel)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} libxquic.so)
endif ()

include_directories( /usr/local/include )
include_directories( ${BABASSL_PATH}/include )
include_directories(${CMAKE_SOURCE_DIR}/)


##### for unit test #########
if (XQC_ENABLE_TESTING)

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

link_directories( /usr/local/lib )
link_directories( ${BABASSL_PATH}/lib/)

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

endif()

