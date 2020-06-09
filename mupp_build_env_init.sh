#!/bin/sh

export IOS_CMAKE_TOOLCHAIN=`pwd`/cmake/ios.toolchain.cmake
chmod +x xqc_build.sh
cp -f bssl_symbols.txt third_party/boringssl/util
./xqc_build.sh ios bss arti

  
