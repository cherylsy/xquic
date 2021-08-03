XQUIC is an implementation for QUIC protocol discussed in IETF QUIC Working Group. 
document space: https://yuque.antfin-inc.com/awm/xquic


## Install openssl
~~~
sudo yum install babassl-8.2.0 -b current -y 
~~~

## Install libevent if you want to run test cases
~~~
sudo yum install libevent -y
sudo yum install libevent-devel -y
~~~

## Build xquic on linux & run test cases
~~~
mkdir build
cd build
sh ../scripts/xquic_test.sh
~~~

## Run test server & client
~~~
./test_server -l d > /dev/null &
./test_client -a 127.0.0.1 -p 8443 -s 1024000 -E
~~~
