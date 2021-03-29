#!/bin/bash

#macOS
#export EVENT_NOKQUEUE=1

cd ../build

# 另一个终端启动server
killall test_server 2> /dev/null
./test_server -l d -e > /dev/null &
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
echo -e "test application delay ...\c"
rm -f xqc_token
./test_client -s 5120 -l d -t 1 -E -x 16 >> clog
if test "$(grep -e "|====>|.*NEW_TOKEN" clog |wc -l)" -gt 1 >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "fin only ...\c"
./test_client -s 5120 -l d -t 1 -E -x 4 |grep ">>>>>>>> pass"
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
echo -e "Reset stream when sending...\c"
./test_client -s 1024000 -l d -t 1 -E -x 1 >> clog
if grep "send_state:5|recv_state:5" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "Reset stream when receiving...\c"
./test_client -s 1024000 -l d -t 1 -E -x 21 >> clog
if grep "send_state:5|recv_state:5" clog >/dev/null && grep "xqc_send_ctl_drop_stream_frame_packets" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v stream

clear_log
echo -e "1RTT ...\c"
./test_client -s 1024000 -l e -t 1 -E -1 >> clog
if grep "early_data_flag:0" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "without session ticket ...\c"
rm -f test_session
./test_client -s 1024000 -l e -t 1 -E >> clog
if grep "early_data_flag:0" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "0RTT accept ...\c"
./test_client -s 1024000 -l e -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "0RTT reject. restart server ....\c"
killall test_server
./test_server -l d -e > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E >> clog
if grep "early_data_flag:2" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "transport only ...\c"
rm -f test_session
./test_client -s 1024000 -l d -T -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "transport 0RTT ...\c"
./test_client -s 1024000 -l e -T -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
rm -f test_session
grep_err_log

clear_log
echo -e "no crypto without 0RTT ...\c"
rm -f test_session
./test_client -s 1024000 -l d -N -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "no crypto with 0RTT ...\c"
./test_client -s 1024000 -l d -N -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log


clear_log
echo -e "no crypto with 0RTT twice ...\c"
./test_client -s 1024000 -l d -N -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
rm -f test_session
echo -e "NULL stream callback ...\c"
killall test_server
./test_server -l d -e -x 2 > /dev/null &
sleep 1
./test_client -l d -T -E >> clog
if grep "stream_read_notify is NULL" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
rm -f test_session

clear_log
echo -e "server cid negotiate ...\c"
killall test_server
./test_server -l d -e -x 1 > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "GET request ...\c"
./test_client -l d -t 1 -E -G|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "client initial version setting ...\c"
./test_client -s 1024 -l d -t 1 -E -x 17 |grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "set h3 settings ...\c"
./test_client -s 1024 -l d -t 1 -E -x 18 >> clog
if grep ">>>>>>>> pass:1" clog >/dev/null && \
   grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:256" clog >/dev/null && \
   grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog >/dev/null && \
   grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog >/dev/null && \
   grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:256" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log

clear_log
echo -e "header size constraints ...\c"
./test_client -s 1024 -l d -t 1 -E -x 19 -n 2 >> clog
if grep -e "xqc_h3_stream_send_headers.*fields_size.*exceed.*SETTINGS_MAX_FIELD_SECTION_SIZE.*" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi
grep_err_log|grep -v xqc_h3_stream_send_headers


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
echo -e "BBR with cwnd compensation ...\c"
./test_client -s 10240000 -l e -t 4 -E -c bbr+|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "BBRv2 ...\c"
./test_client -s 10240000 -l e -t 4 -E -c bbr2|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "BBRv2+ ...\c"
./test_client -s 10240000 -l e -t 4 -E -c bbr2+|grep ">>>>>>>> pass"
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
echo -e "Cubic (Kernel) with pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c C -C|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "Cubic (Kernel) without pacing ...\c"
./test_client -s 10240000 -l e -t 3 -E -c C|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "spurious loss detect on ...\c"
./test_client -s 10240000 -l e -t 3 -E -x 26|grep ">>>>>>>> pass"
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
./test_client -s 10240000 -l e -t 7 -E -d 30|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "10% loss ...\c"
./test_client -s 10240000 -l e -t 12 -E -d 100|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "sendmmsg with 10% loss ...\c"
./test_client -s 10240000 -l e -t 12 -E -d 100 -x 20 -c c|grep ">>>>>>>> pass"
grep_err_log

clear_log
echo -e "large ack range with 30% loss ...\c"
./test_client -s 2048000 -l e -t 3 -E -d 300|grep ">>>>>>>> pass"


clear_log
killall test_server
echo -e "client Initial dcid corruption ...\c"
./test_server -l d -e > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 3 -x 22 -E | grep ">>>>>>>> pass"`
server_log_res=`grep "decrypt data error" slog`
server_conn_cnt=`grep "xqc_conn_create" slog | wc -l`
if [ "$client_print_res" != "" ] && [ "$server_log_res" != "" ] && [ $server_conn_cnt -eq 2 ]
then
    echo "$client_print_res"
fi

clear_log
killall test_server
echo -e "client Initial scid corruption ...\c"
./test_server -l d -e > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 3 -x 23 -E | grep ">>>>>>>> pass"`
server_log_res=`grep "decrypt data error" slog`
server_dcid_res=`grep "dcid change" slog`
if [ "$client_print_res" != "" ] && [ "$server_log_res" != NULL ] && [ "$server_dcid_res" != NULL ]
then
    echo "$client_print_res"
fi

clear_log
killall test_server
echo -e "server Initial dcid corruption ...\c"
./test_server -l d -e -x 3 > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 3 -E |grep ">>>>>>>> pass"`
client_log_res=`grep "fail to find connection" clog`
if [ "$client_print_res" != "" ]
then
    echo "$client_print_res"
fi

clear_log
killall test_server
echo -e "server Initial scid corruption ...\c"
./test_server -l d -e -x 4 > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 3 -E |grep ">>>>>>>> pass"`
client_log_res=`grep "decrypt data error" clog`
if [ "$client_print_res" != "" ] && [ "$client_log_res" != NULL ]
then
    echo "$client_print_res"
fi

clear_log
killall test_server
echo -e "server odcid hash ...\c"
./test_server -l d -e -x 5 > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 3 -E | grep ">>>>>>>> pass"


clear_log
killall test_server
echo -e "server odcid hash failure ...\c"
./test_server -l d -e -x 6 > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 3 -x 24 > /dev/null
sleep 11
server_log_res=`grep "remove abnormal odcid conn hash" slog`
if [ "$server_log_res" != "" ]
then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi


clear_log
killall test_server 2> /dev/null
echo -e "enable_multipath_negotiate ...\c"
./test_server -l d -e -x 7 > /dev/null &
sleep 1
result=`./test_client -s 1024000 -l d -t 3 -x 25 | grep "enable_multipath=1"`
if [ "$result" != "" ]
then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi


clear_log
killall test_server 2> /dev/null
echo -e "load balancer cid generate ...\c"
./test_server -l d -e -S "server_id_0" > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 3 >> clog
result=`grep "|xqc_conn_confirm_cid|dcid change|" clog | grep "7365727665725f69645f30"`
if [ "$result" != "" ]
then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi



killall test_server

cd -
