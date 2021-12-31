# Copyright (c) 2022, Alibaba Group Holding Limited

#!/bin/bash

cd ../build

server_ip=$1
server_port=$2

if [ $# -lt 2 ];
then
    echo 'More parameters required!'
    echo 'sh nginx_test.sh [server_ip] [server_port]'
    exit
fi

#macOS
#export EVENT_NOKQUEUE=1


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

echo "server_ip: ${server_ip}, port:${server_port}"

clear_log
echo -e "stream read notify fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 12 -a ${server_ip} -p ${server_port} >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_process_read_streams|grep -v xqc_h3_stream_read_notify|grep -v xqc_process_conn_close_frame

clear_log
echo -e "create stream fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 11 -a ${server_ip} -p ${server_port} >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_stream_create

clear_log
echo -e "illegal packet ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 10 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "duplicate packet ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 9 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "packet with wrong cid ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 8 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "create connection fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 7 -a ${server_ip} -p ${server_port} >> clog
echo ">>>>>>>> pass:1"
grep_err_log|grep -v xqc_client_connect

clear_log
echo -e "socket recv fail ...\c"
./test_client -s 1024000 -l d -t 2 -E -x 6 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "socket send fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 5 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log|grep -v "write_socket error"

clear_log
echo -e "verify Token fail ...\c"
rm -f xqc_token
./test_client -s 1024000 -l d -t 1 -E -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log|grep -v xqc_conn_check_token

clear_log
echo -e "verify Token success ...\c"
./test_client -s 1024000 -l d -t 1 -E -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "fin only ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 4 -a ${server_ip} -p ${server_port} |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "user close connection ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 2 -a ${server_ip} -p ${server_port} >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "====>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "close connection with error ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 3 -a ${server_ip} -p ${server_port} >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "====>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v xqc_process_write_streams|grep -v xqc_h3_stream_write_notify|grep -v xqc_process_conn_close_frame


clear_log
echo -e "Reset stream ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 1 -a ${server_ip} -p ${server_port} >> clog
if grep "send_state:5|recv_state:5" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "1RTT ...\c"
./test_client -s 1024000 -l d -t 1 -E -1 -a ${server_ip} -p ${server_port} >> clog
if grep "early_data_flag:0" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "0RTT accept ...\c"
./test_client -s 1024000 -l d -t 1 -E -a ${server_ip} -p ${server_port} >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log


## for 0-RTT reject ######
clear_log
echo -e "0RTT reject. restart server ....\c"
sudo pkill -INT nginx
sudo -u admin sed "s/session_ticket\.key/session_ticket_2\.key/g" /home/admin/cai/conf/nginx-quic.conf -i
sudo -u admin -H /home/admin/cai/bin/nginx -c /home/admin/cai/conf/nginx-quic.conf -p /home/admin/cai
#killall test_server
#./test_server -l e -e > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E -a ${server_ip} -p ${server_port} >> clog
if grep "early_data_flag:2" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

sudo pkill -INT nginx
sudo -u admin sed "s/session_ticket_2\.key/session_ticket\.key/g" /home/admin/cai/conf/nginx-quic.conf -i
sudo -u admin -H /home/admin/cai/bin/nginx -c /home/admin/cai/conf/nginx-quic.conf -p /home/admin/cai
sleep 1
## end 0-RTT reject ######

clear_log
echo -e "GET request ...\c"
./test_client -l d -t 1 -E -G -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 1K data ...\c"
./test_client -s 1024 -l d -t 1 -E -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 1M data ...\c"
./test_client -s 1024000 -l d -t 1 -E -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "send 10M data ...\c"
./test_client -s 10240000 -l e -t 4 -E -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "BBR ...\c"
./test_client -s 10240000 -l e -t 4 -E -c bbr -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Reno with pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c reno -C -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Reno without pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c reno -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Cubic with pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c cubic -C -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Cubic without pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c cubic -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "stream level flow control ...\c"
./test_client -s 10240000 -l e -t 4 -E -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "connection level flow control ...\c"
./test_client -s 512000 -l e -t 3 -E -n 10 -a ${server_ip} -p ${server_port} >> clog
if [[ `grep ">>>>>>>> pass:1" clog|wc -l` -eq 10 ]]; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "stream concurrency flow control ...\c"
./test_client -s 1 -l e -t 2 -E -P 1025 -G -a ${server_ip} -p ${server_port} >> clog
if [[ `grep ">>>>>>>> pass:1" clog|wc -l` -eq 1024 ]]; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "1% loss ...\c"
./test_client -s 10240000 -l e -t 4 -E -d 10 -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "3% loss ...\c"
./test_client -s 10240000 -l e -t 4 -E -d 30 -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "10% loss ...\c"
./test_client -s 10240000 -l e -t 10 -E -d 100 -a ${server_ip} -p ${server_port}|grep ">>>>>>>> pass"
grep_err_log

#killall test_server

cd -
