#!/bin/bash

#macOS
#export EVENT_NOKQUEUE=1

# 另一个终端启动server
killall test_server 2> /dev/null
./test_server -l e -e > /dev/null &
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

#clear_log
#echo -e "变长cid_len ...\c"
#./test_client -s 1024000 -l d -t 1 -E -x 13|grep ">>>>>>>> pass"
#grep_err_log

clear_log
echo -e "stream read notify fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 12 >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_process_read_streams|grep -v xqc_h3_stream_read_notify|grep -v xqc_process_conn_close_frame

clear_log
echo -e "create stream fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 11 >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_stream_create

clear_log
echo -e "illegal packet ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 10|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "duplicate packet ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 9|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "packet with wrong cid ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 8|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "create connection fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 7 >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_client_connect

clear_log
echo -e "socket recv fail ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 6|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "socket send fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 5|grep ">>>>>>>> pass"
grep_err_log|grep -v "write_socket error"

clear_log
echo -e "verify Token fail ...\c"
rm -f xqc_token
./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"
grep_err_log|grep -v xqc_conn_check_token

clear_log
echo -e "verify Token success ...\c"
./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "fin only ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 4 |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "user close connection ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 2 >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "====>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "close connection with error ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 3 >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "====>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v xqc_process_write_streams|grep -v xqc_h3_stream_write_notify|grep -v xqc_process_conn_close_frame


clear_log
echo -e "Reset stream ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 1 >> clog
if grep "send_state:5|recv_state:5" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "1RTT ...\c"
./test_client -s 1024000 -l d -t 1 -E -1 >> clog
if grep "early_data_flag:0" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "0RTT accept ...\c"
./test_client -s 1024000 -l d -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "0RTT reject. restart server ....\c"
killall test_server
./test_server -l e -e > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E >> clog
if grep "early_data_flag:2" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "GET request ...\c"
./test_client -l d -t 1 -E -G|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 1K data ...\c"
./test_client -s 1024 -l d -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 1M data ...\c"
./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 10M data ...\c"
./test_client -s 10240000 -l e -t 4 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "BBR ...\c"
./test_client -s 10240000 -l e -t 4 -E -c bbr|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Reno with pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c reno -C|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Reno without pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c reno|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Cubic with pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c cubic -C|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Cubic without pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c cubic|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "stream level flow control ...\c"
./test_client -s 10240000 -l e -t 4 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "connection level flow control ...\c"
./test_client -s 512000 -l e -t 3 -E -n 10 >> clog
if [[ `grep ">>>>>>>> pass:1" clog|wc -l` -eq 10 ]]; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "stream concurrency flow control ...\c"
./test_client -s 1 -l e -t 2 -E -P 1025 -G >> clog
if [[ `grep ">>>>>>>> pass:1" clog|wc -l` -eq 1024 ]]; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "1% loss ...\c"
./test_client -s 10240000 -l e -t 4 -E -d 10|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "3% loss ...\c"
./test_client -s 10240000 -l e -t 4 -E -d 30|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "10% loss ...\c"
./test_client -s 10240000 -l e -t 10 -E -d 100|grep ">>>>>>>> pass"
grep_err_log

killall test_server