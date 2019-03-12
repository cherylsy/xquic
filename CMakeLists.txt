cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -std=c11")
 
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

    transport/xqc_conn.c
)

set(
    COMMON_SOURCES

    common/xqc_mem.c
)

add_library(
    xquic

    STATIC
    
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
)

add_executable(test_server tests/test_server.c)

include_directories( /usr/local/include )
link_directories( /usr/local/lib )

target_link_libraries(test_server xquic)
