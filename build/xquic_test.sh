#!/bin/bash

> xquic_test.log

#生成证书
if [[ ! -f "server.key" || ! -f "server.crt" ]]; then
keyfile=server.key
certfile=server.crt
openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=localhost
fi

#安装批量输出工具，否则只能按单个文件输出结果
sudo yum -y install python-pip > /dev/null
sudo yum -y install python-lxml > /dev/null
sudo pip install gcovr > /dev/null

#编译开启Code Coverage
cmake -DGCOV=on ..
#make clean
make -j

# "unit test..."
./tests/run_tests | tee -a xquic_test.log

# "case test..."
./case_test.sh | tee -a xquic_test.log

#批量输出所有文件的覆盖率和工程覆盖率统计
gcovr -r .. | tee -a xquic_test.log

#关闭Code Coverage
cmake .. -DGCOV=off

#最终结果输出
echo "=============summary=============="
echo -e "unit test:"
cat xquic_test.log | grep "Test:"
passed=`cat xquic_test.log | grep "Test:" | grep "passed" | wc -l`
failed=`cat xquic_test.log | grep "Test:" | grep "FAILED" | wc -l`
echo -e "\033[32m passed:$passed failed:$failed \033[0m"

echo -e "\ncase test:"
cat xquic_test.log | grep "pass:"
passed=`cat xquic_test.log | grep "pass:" | grep "pass:1" | wc -l`
failed=`cat xquic_test.log | grep "pass:" | grep "pass:0" | wc -l`
echo -e "\033[32m passed:$passed failed:$failed \033[0m"

echo -e "\nCode Coverage:                             Lines    Exec  Cover"
cat xquic_test.log | grep "TOTAL"

