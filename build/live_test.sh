#!/bin/bash

# 另一个终端启动server
#killall test_server 2> /dev/null
#./test_server -l e -s 10240000
#sleep 1

>live_test.log
for ((i=0;i<100;i++))
do
    ./test_client -s 99 -l e -t 1 -x 14 -T|grep ">>>>>>>> first_frame pass\|>>>>>>>> abnormal pass" |tee -a live_test.log
done
wait
cat live_test.log |grep ">>>>>>>> first_frame pass"|awk '{print $3}'|awk -F ":" '{print $2}'|awk '{sum+=$1;} END {printf("ReqNum = %d\nmiaokai_rate = %f\n", NR, sum/NR)}'
cat live_test.log |grep ">>>>>>>> abnormal pass"|awk '{print $3}'|awk -F ":" '{print $2}'|awk '{sum+=$1;} END {printf("ReqNum = %d\nabnormal_rate = %f\n", NR, 1 - sum/NR)}'