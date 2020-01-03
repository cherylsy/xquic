#!/bin/bash

# 另一个终端启动server
#./test_server -l e -s 1

>pressure_test.log
for ((i=0;i<10;i++))
do
    ./test_client -a 203.119.191.203 -p 443 -s 1000000 -l e -t 3 -n 10|grep ">>>>>>>> request time cost" |tee -a pressure_test.log &
done
wait
cat pressure_test.log |awk '{print $4}'|awk -F ":" '{print $2}'|awk '{sum+=$1;} END {printf("ReqNum = %d\nAverage cost = %d", NR, sum/NR)}'