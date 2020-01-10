#!/bin/bash

# 另一个终端启动server
#killall test_qpack_server 2> /dev/null
#./test_qpack_server  > /dev/null &
sleep 1

clear_log() {
    >clog
    >slog
}

grep_err_log() {
    grep "\[error\]" clog
    grep "\[error\]" slog
    grep "retrans rate:" clog|grep -v "retrans rate:0.0000"
    grep "retrans rate:" slog|grep -v "retrans rate:0.0000"
}

grep_qpack_test_result() {
    grep "qpack test " clog
}

clear_log
echo "测试qpack never flag:"
echo "测试qpack 哈希表insert:"
echo "测试qpack literial 编码:"
echo "测试qpack name value index:"
echo "测试qpack name index:"
./test_qpack_client | grep "qpack test" 
grep_qpack_test_result
grep_err_log|grep -v xqc_conn_check_token

