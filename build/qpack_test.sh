#!/bin/bash

# 另一个终端启动server
killall test_qpack_server 2> /dev/null
./test_qpack_server  > /dev/null &
sleep 1

clear_log() {
    >clog
    >slog
}

grep_err_log() {
    grep "\[error\]" clog
    grep "\[error\]" slog
    #grep "retrans rate:" clog|grep -v "retrans rate:0.0000"
    #grep "retrans rate:" slog|grep -v "retrans rate:0.0000"
}

grep_qpack_test_result() {
    grep "qpack test " clog
}

clear_log
#echo "[1]测试qpack insert literial:"
#echo "[2]测试qpack never flag:"
#echo "[3]测试qpack literial 模式发送:"
#echo "[4]测试qpack 静态表 static name value index 编码:"
#echo "[5]测试qpack 静态表 static name index 编码:"
#echo "[6]测试qpack 动态表 name value index 编码:"
#echo "[7]测试qpack 动态表 name index 编码:"
#echo "[8]测试qpack 动态表 draining:"
./test_qpack_client | grep "qpack test" 
grep_qpack_test_result
grep_err_log|grep -v xqc_conn_check_token

killall test_qpack_server