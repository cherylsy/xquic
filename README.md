XQUIC is an implementation for QUIC protocol discussed in IETF QUIC Working Group. 
document space: https://yuque.antfin-inc.com/awm/xquic


## install openssl
sudo yum install babassl-8.1.4 -b current -y 

## if you want to run test cases, install libevent
sudo yum install libevent -y
sudo yum install libevent-devel -y

## build xquic on linux & run test cases
mkdir build
cd build
sh ../scripts/xquic_test.sh

## run test server & client
./test_server -l d > /dev/null &
./test_client -a 127.0.0.1 -p 8443 -s 1024000 -E
