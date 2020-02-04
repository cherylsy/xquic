#!/bin/bash
rm -rf CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake_install.cmake
rm -rf Makefile
rm -rf CTestTestfile.cmake

if [ $1 = "32" ]; then
MINGW=/home/jiuhai.zjh/mingw
export PATH=$MINGW/bin:$PATH
cmake \
      -DCMAKE_TOOLCHAIN_FILE=$MINGW/windows.toolchain.cmake \
      -D_WIN32_WINNT=0x0600 \
      -DUSE_32BITS=1 \
      ..;
make VERBOSE=1 -j4;
else
MINGW=/home/jiuhai.zjh/mingw64
export PATH=$MINGW/bin:$PATH
cmake \
      -DCMAKE_TOOLCHAIN_FILE=$MINGW/windows.toolchain.cmake \
      -D_WIN32_WINNT=0x0600 \
      ..;
make VERBOSE=1 -j4;
fi
