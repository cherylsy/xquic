# XQUIC

## Introduction

XQUIC Library released by Alibaba is …

… **a client and server implementation of QUIC and HTTP/3 as specified by the IETF.** Currently supported QUIC versions are v1 and draft-29.

… **OS and platform agnostic.** It currently supports Android, iOS, Linux and MacOS. Most of the code is used in our own products, and has been tested at scale on android, iOS apps, as well as servers.

… **still in active development.** [Interoperability](https://interop.seemann.io/) is regularly tested with other QUIC implementations.

## Requirements

To build XQUIC, you need 
- CMake
- BoringSSL/BabaSSL

To run test cases, you need
- libevent
- CUnit

## QuickStart Guide
xquic supports both BabaSSL and Boringssl.

### Build with BabaSSL

```bash
# get and build babassl
git clone https://github.com/BabaSSL/BabaSSL.git
cd BabaSSL/
./config --prefix=/usr/local/babassl
make -j
SSL_PATH_STR="${PWD}"
SSL_INC_PATH_STR="${PWD}/include"
SSL_LIB_PATH_STR="${PWD}/libssl.a;${PWD}/libcrypto.a"
cd ..

# get and build xquic
git clone git@github.com:alibaba/xquic.git
cd xquic
git submodule update --init --recursive
mkdir build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_PRINT_SECRET=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### Build with BoringSSL

```bash
# get and build boringssl
git clone https://github.com/google/boringssl.git
cd boringssl
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make ssl crypto
SSL_PATH_STR="${PWD}"
SSL_INC_PATH_STR="${PWD}/include"
SSL_LIB_PATH_STR="${PWD}/build/ssl/libssl.a;${PWD}/build/crypto/libcrypto.a"
cd ../..

# get and build xquic
git clone git@github.com:alibaba/xquic.git
cd xquic
git submodule update --init --recursive
mkdir build
cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_PRINT_SECRET=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### Run testcases
```bash
sh ../scripts/xquic_test.sh
```

## Documentation

- For using the API, see the [API docs](./docs/API.md).
- For platform support details, see the [Platforms docs](./docs/Platforms.md).
- For other frequently asked questions, see the [FAQs](./docs/FAQ.md).

## Contributing

We would love for you to contribute to XQUIC and help make it even better than it is today! All types of contributions are encouraged and valued. See our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

If you have any questions, please feel free to open a new Discussion topic in our [discussion forums](https://github.com/alibaba/xquic/discussions).

## License

XQUIC is released under the Apache 2.0 License.

## All-contributors

Thanks goes to these wonderful people:

- 刘彦梅（喵吉）
- 赵武（赤杨）
- 章玖海（以天）
- 陈文韬（静笃）
- 张渊博（辰帆）
- 周瑞祺（凼凼）
- 郑智隆（之有）
- 李亮（觉问）
- 施威（不达）
- 杨馥榕（暁陽）
- 左春伟（酱油）
- 唐颖琦（陆花）
- 胡军伟（苍茫）
- 徐盟欣（象谦）
- 杜叶飞（淮叶）
- 吕格瑞（林曙）
- 曾柯（毅丝）
- 倪蕴哲
- 罗凯（懿彬）








