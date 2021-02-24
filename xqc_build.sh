#!/bin/sh

android_archs=(armeabi-v7a arm64-v8a)
ios_archs=(armv7 arm64 x86_64)
cur_dir=$(cd "$(dirname "$0")";pwd)

cp -f $cur_dir/cmake/CMakeLists.txt  $cur_dir/CMakeLists.txt 

platform=$1
build_dir=$2
artifact_dir=$3

create_dir_or_exit(){
	if [ x"$2" == x ] ; then
		echo "$1不能为空"
		exit 1
	fi
	if [ -d $2 ] ; then
		echo "目录已存在"
	else 
		mkdir $2 
		echo "创建$1目录($2) 成功" 
	fi
}

platform=$(echo $platform | tr A-Z a-z ) 

if [ x"$platform" == xios ] ; then 
	if [ x"$IOS_CMAKE_TOOLCHAIN" == x ] ; then
		echo "必须定义一个IOS_CMAKE_TOOLCHAIN:" 
		exit 0
	fi
	archs=${ios_archs[@]} 
	configures="-DXQC_OPENSSL_IS_BORINGSSL=on -DBORINGSSL_PREFIX=bs -DBORINGSSL_PREFIX_SYMBOLS=$cur_dir/bssl_symbols.txt  -DDEPLOYMENT_TARGET=10.0  -DCMAKE_BUILD_TYPE=Minsizerel -DXQC_ENABLE_TESTING=OFF -DXQC_BUILD_SAMPLE=OFF -DGCOV=OFF -DCMAKE_TOOLCHAIN_FILE=${IOS_CMAKE_TOOLCHAIN} -DENABLE_BITCODE=0 -DXQC_NO_SHARED=1" 
elif [ x"$platform" == xandroid ] ; then 
	if [ x"$ANDROID_NDK" == x ] ; then 
		echo "必须定义ANDROID_NDK" 
		exit 0 	
	fi	
	archs=${android_archs[@]}
	configures="-DCMAKE_BUILD_TYPE=Minsizerel
	            -DXQC_ENABLE_TESTING=OFF
	            -DXQC_BUILD_SAMPLE=OFF
	            -DGCOV=OFF
	            -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
	            -DANDROID_STL=c++_shared
	            -DANDROID_NATIVE_API_LEVEL=android-19
	            -DXQC_DISABLE_RENO=on"
else 
	echo "no support platform"
	exit 0
fi


generate_plat_spec() {
	plat_spec=
	if [ x"$platform" == xios ] ; then 
		plat_spec="-DARCHS=$1"
		if [ x"$1" == xx86_64 ] ; then 
			plat_spec="$plat_spec -DPLATFORM=SIMULATOR64"
		elif [ x"$1" == xi386 ] ; then 
			plat_spec="$plat_spec -DPLATFORM=SIMULATOR"
		fi  	
	else 
		plat_spec="-DANDROID_ABI=$1"	
	fi
	echo $plat_spec
}

create_dir_or_exit 构建 $build_dir
# to absoulute path 
build_dir=$cur_dir/$build_dir

create_dir_or_exit 产物 $artifact_dir 
artifact_dir=$cur_dir/$artifact_dir 

cd $build_dir 

for i in ${archs[@]} ; 
do
	rm -f  CMakeCache.txt	
	rm -rf CMakeFiles
	rm -rf Makefile	
	rm -rf cmake_install.cmake
	rm -rf include	
	rm -rf outputs	
	rm -rf third_party
	
	echo "编译$i 架构"
	cmake  $configures  $(generate_plat_spec $i ) -DLIBRARY_OUTPUT_PATH=`pwd`/outputs/ .. 
	make -j 4
	if [ $? != 0 ] ; then
		exit 0
	fi

	if [ ! -d  ${artifact_dir}/$i ] ; then 
		mkdir -p ${artifact_dir}/$i  
	fi	
	cp -f `pwd`/outputs/*.a 	${artifact_dir}/$i/ 
	cp -f `pwd`/outputs/*.so	 ${artifact_dir}/$i/
done


make_fat() {
	script="lipo -create"
	for i in ${archs[@]} ;
	do
		script="$script -arch $i $artifact_dir/$i/$1  "
	done
	script="$script -output $cur_dir/ios/xquic/xquic/Libs/$1"
	$($script) 
}


if [ x"$platform" == xios ] ; then
	if [ ! -d $cur_dir/ios/xquic/xquic/Headers ] ; then  
		mkdir -p $cur_dir/ios/xquic/xquic/Headers 
	fi
	if [ ! -d $cur_dir/ios/xquic/xquic/Libs ] ; then
		mkdir -p $cur_dir/ios/xquic/xquic/Libs
	fi
	make_fat libxquic.a
	make_fat libcrypto.a
	make_fat libssl.a	
	cp -f $cur_dir/include/xquic/*   $cur_dir/ios/xquic/xquic/Headers/ 
	cp -f $build_dir/include/xquic/* $cur_dir/ios/xquic/xquic/Headers/	

fi



	
