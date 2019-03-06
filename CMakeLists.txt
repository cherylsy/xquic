cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)
 
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

    SHARED
    
    ${TRANSPORT_SOURCES}
    ${COMMON_SOURCES}
)

add_executable(test_server test_server.c)

target_link_libraries(test_server xquic)
