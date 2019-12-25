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
}

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
./test_client -s 10240000 -l e -t 1 -E|grep "******** pass"
grep_err_log

clear_log
echo "验证0RTT"
./test_client -s 1024000 -l e -t 1 -E|grep "******** pass"
grep_err_log