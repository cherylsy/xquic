#!/bin/bash
#abis=("armeabi-v7a" "arm64-v8a" "x86" "x86_64")

abi="armeabi-v7a"
rm -rf CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake_install.cmake
rm -rf Makefile
rm -rf CTestTestfile.cmake
/home/jiuhai.zjh/cmake-3.15.4-Linux-x86_64/bin/cmake \
      -DCMAKE_TOOLCHAIN_FILE=/home/jiuhai.zjh/android-ndk-r17c/build/cmake/android.toolchain.cmake \
      -DANDROID_NDK=/home/jiuhai.zjh/android-ndk-r17c \
      -DANDROID_ABI=$abi \
      -DANDROID_TOOLCHAIN=gcc \
      -DANDROID_PLATFORM=android-16 \
      -DANDROID_PIE=YES \
      -DANDROID_ALLOW_UNDEFINED_SYMBOLS=YES\
      ..;
make VERBOSE=1 -j4 xquic;
mv libxquic.so libxquic.so.$abi

abi="arm64-v8a"
rm -rf CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake_install.cmake
rm -rf Makefile
rm -rf CTestTestfile.cmake
/home/jiuhai.zjh/cmake-3.15.4-Linux-x86_64/bin/cmake \
      -DCMAKE_TOOLCHAIN_FILE=/home/jiuhai.zjh/android-ndk-r17c/build/cmake/android.toolchain.cmake \
      -DANDROID_NDK=/home/jiuhai.zjh/android-ndk-r17c \
      -DANDROID_ABI=$abi \
      -DANDROID_TOOLCHAIN=gcc \
      -DANDROID_PLATFORM=android-21 \
      -DANDROID_PIE=YES \
      -DANDROID_ALLOW_UNDEFINED_SYMBOLS=YES\
      ..;
make VERBOSE=1 -j4 xquic;
mv libxquic.so libxquic.so.$abi