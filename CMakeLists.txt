cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_C_STANDARD 11 )
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_MODULE_PATH       "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

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

if(ANDROID)
    set(DYMAMIC_LINX_OPTION "${DYMAMIC_LINX_OPTION} -lm -llog")
    if(NOT ANDROID_TOOLCHAIN_ROOT)
        message(FATAL_ERROR  "You Must Define DANDROID_TOOLCHAIN_ROOT")
    endif()
endif()

include(CMakeOptions.txt)


if (XQC_WITH_OPENSSL)
    set(XQC_TLS_BUILD_WITH_OPENSSL 1)
    if(XQC_OPENSSL_IS_BORINGSSL) 
        add_subdirectory(third_party/boringssl)
        include_directories(third_party/boringssl/include)
    else()
        set(EXTRA_CONFIGURE_OPENSSL_PARAMS "${EXTRA_CONFIGURE_OPENSSL_PARAMS} ${DYNAMIC_COMPILE_FLAGS} ")
        add_subdirectory(external/openssl-cmake)
    endif()
endif()


configure_file (xqc_configure.h.in include/xquic/xqc_configure.h  @ONLY)

include_directories(
    include/ 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/include
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
    )

set (
    
    CRYPTO_SOURCE

    "src/crypto/xqc_tls_init.c"
    "src/crypto/xqc_crypto.c"
    "src/crypto/xqc_tls_cb.c"
    "src/crypto/xqc_tls_0rtt.c"
    "src/crypto/xqc_tls_if.c"

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
    SHARED
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${CRYPTO_SOURCE}
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
