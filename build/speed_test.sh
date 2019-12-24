#!/bin/bash

>speed_test.log
for ((i=0;i<30;i++))
do
    ./test_client -a 203.119.191.203 -p 443 -s 1000000 -l e -t 1|grep "******** request time cost" |tee speed_test.log
done
cat speed_test.log |awk '{print $4}'|awk -F ":" '{print $2}'|awk '{sum+=$1; print $1} END {print "Average cost = ", sum/NR}'