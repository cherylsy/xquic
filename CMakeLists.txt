cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_C_STANDARD 11 )
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(COMMON_FLAGS            "-Werror -Wall -Wno-deprecated  -Wno-unused -Wno-pointer-sign -Wno-format-security ")

set(COMMON_RELEASE_FLAGS    "-DNDEBUG")
set(COMMON_MIN_FLAGS        " ${COMMON_RELEASE_FLAGS} -Os -ffunction-sections -fdata-sections -fvisibility=hidden")
set(COMMON_DEBUG_FLAGS     "-pg -O0")
if(GCOV)
    set(COMMON_DEBUG_FLAGS "${COMMON_DEBUG_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

if (CMAKE_BUILD_TYPE STREQUAL Release)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_RELEASE_FLAGS})
elseif(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_DEBUG_FLAGS})
elseif(CMAKE_BUILD_TYPE STREQUAL Minsizerel)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_MIN_FLAGS})
	set(DYMAMIC_LINX_OPTION "-Wl,--gc-sections")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS} ${DYNAMIC_COMPILE_FLAGS}")

configure_file (
    xqc_cmake_config.h.in
    xqc_cmake_config.h
)

if(ANDROID)
    set(DYMAMIC_LINX_OPTION "${DYMAMIC_LINX_OPTION} -lm -llog")
    if(NOT ANDROID_TOOLCHAIN_ROOT)
        message(FATAL_ERROR  "You Must Define DANDROID_TOOLCHAIN_ROOT")
    endif()
endif()

set(EXTRA_CONFIGURE_OPENSSL_PARAMS "${EXTRA_CONFIGURE_OPENSSL_PARAMS} ${DYNAMIC_COMPILE_FLAGS} ")
add_subdirectory(external/openssl-cmake)

include(CMakeOptions.txt)

include_directories(
    http3
    transport
    transport/crypto
    common
    congestion_control
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

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
    SHARED
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)

target_link_libraries(
    xquic 
    ssl
    crypto
    -pthread
    ${DYMAMIC_LINX_OPTION}
)

#add_subdirectires(third_party/libevent) 
#add_executable(test_client tests/test_client.c)
#target_link_libraries(xquic event add_executable(test_client tests/test_client.c)

#add_executable(test_client tests/test_client.c)
#add_executable(test_server tests/test_server.c)

#target_link_libraries(test_client xquic -levent)
#target_link_libraries(test_server xquic -levent)
