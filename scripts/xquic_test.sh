#!/bin/bash

function generate_cert() {
    #生成证书
    if [[ ! -f "server.key" || ! -f "server.crt" ]]; then
    keyfile=server.key
    certfile=server.crt
    openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=localhost
    fi
}

function install_gcov_tool() {
    #安装批量输出工具，否则只能按单个文件输出结果
    sudo yum -y install python-pip > /dev/null
    sudo yum -y install python-lxml > /dev/null
    sudo pip install gcovr > /dev/null
}


function do_compile() {
    rm -f CMakeCache.txt
    if [[ $1 == "XQC_OPENSSL_IS_BORINGSSL" ]]; then
        #compile boringssl
        mkdir -p ../third_party/boringssl/build
        cd ../third_party/boringssl/build
        cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
        make ssl crypto
        cd -

        cmake -DXQC_OPENSSL_IS_BORINGSSL=1 ..
    fi

    #编译开启Code Coverage
    cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug ..
    #make clean
    make -j

    rm -f CMakeCache.txt
}

function run_test_case() {
    # "unit test..."
    ./tests/run_tests | tee -a xquic_test.log

    # "case test..."
    sh ../scripts/case_test.sh | tee -a xquic_test.log

    # "qpack test..."
    sh ../scripts/qpack_test.sh | tee -a xquic_test.log
}

function run_gcov() {
    #批量输出所有文件的覆盖率和工程覆盖率统计
    gcovr -r .. | tee -a xquic_test.log
}

function output_summary() {
    #最终结果输出
    echo "=============summary=============="
    echo -e "unit test:"
    cat xquic_test.log | grep "Test:"
    passed=`cat xquic_test.log | grep "Test:" | grep "passed" | wc -l`
    failed=`cat xquic_test.log | grep "Test:" | grep "FAILED" | wc -l`
    echo -e "\033[32m unit test passed:$passed failed:$failed \033[0m"

    echo -e "\ncase test:"
    cat xquic_test.log | grep "pass:"
    passed=`cat xquic_test.log | grep "pass:" | grep "pass:1" | wc -l`
    failed=`cat xquic_test.log | grep "pass:" | grep "pass:0" | wc -l`
    echo -e "\033[32m case test passed:$passed failed:$failed \033[0m"

    echo -e "\nqpack test:"
    cat xquic_test.log | grep "qpack test" | grep ">>"
    passed=`cat xquic_test.log | grep "qpack test" | grep "pass" | wc -l`
    failed=`cat xquic_test.log | grep "qpack test" | grep "failed" | wc -l`
    echo -e "\033[32m qpack test passed:$passed failed:$failed \033[0m"

    echo -e "\nCode Coverage:                             Lines    Exec  Cover"
    cat xquic_test.log | grep "TOTAL"
}

cd ../build

> xquic_test.log

generate_cert
install_gcov_tool

#run boringssl
do_compile "XQC_OPENSSL_IS_BORINGSSL"
run_test_case
#run babassl
do_compile
run_test_case

run_gcov
output_summary

cd -
