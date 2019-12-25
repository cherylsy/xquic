#!/bin/bash

# 另一个终端启动server
#./test_server -l e -e

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

clear_log
echo "验证Token失效"
rm -f xqc_token
./test_client -s 1024000 -l e -t 1 -E|grep "******** pass"
grep_err_log|grep -v xqc_conn_check_token

clear_log
echo "验证Token生效"
./test_client -s 1024000 -l e -t 1 -E|grep "******** pass"
grep_err_log

clear_log
echo "验证1RTT"
./test_client -s 1024000 -l e -t 1 -E -1 >> clog
if grep "early_data_flag:0" clog >/dev/null && grep "******** pass:1" clog >/dev/null; then
    echo "******** pass:1"
else
    echo "******** pass:0"
fi
grep_err_log

clear_log
echo "验证0RTT"
./test_client -s 1024000 -l e -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep "******** pass:1" clog >/dev/null; then
    echo "******** pass:1"
else
    echo "******** pass:0"
fi
grep_err_log

clear_log
echo "发送1K"
./test_client -s 1024 -l e -t 1 -E|grep "******** pass"
grep_err_log

clear_log
echo "发送1M"
./test_client -s 1024000 -l e -t 1 -E|grep "******** pass"
grep_err_log

clear_log
echo "发送10M"
./test_client -s 10240000 -l e -t 2 -E|grep "******** pass"
grep_err_log

