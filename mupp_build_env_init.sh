#!/bin/sh

export IOS_CMAKE_TOOLCHAIN=`pwd`/cmake/ios.toolchain.cmake
chmod +x xqc_build.sh
./xqc_build.sh ios bss arti

  
