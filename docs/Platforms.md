# Platforms docs

XQUIC currently supports `Android`, `iOS`, `Linux` and `MacOS`.

## Android/iOS Compile Script

The Android and iOS use `.so` files, there is a `xqc_build.sh` script in the xquic library directory, execute the script to compile to complete the corresponding compilation.

```bash
sh xqc_build.sh ios/android <build_dir> <artifact_dir>
```

> Note: You need to specify the IOS/andriod build toolchain before compiling, download and set the environment variable IOS_CMAKE_TOOLCHAIN or ANDROID_NDK, or directly modify CMAKE_TOOLCHAIN_FILE in xqc_build.sh
