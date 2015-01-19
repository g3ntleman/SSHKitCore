#!/bin/bash


BASE_DIR=`pwd`

# pushd .
# cd $BASE_DIR/openssl

# ./openssl-build.sh

# popd

pushd .
cd $BASE_DIR/libssh/build/
cmake -DCMAKE_PREFIX_PATH=$BASE_DIR/openssl/dist/openssl-1.0.1l-MacOSX -DOPENSSL_ROOT_DIR= -DCMAKE_INSTALL_PREFIX=./dist -DCMAKE_BUILD_TYPE=MinSizeRel -DWITH_SSH1=OFF -DWITH_STATIC_LIB=ON -DWITH_SERVER=ON -MACOSX_DEPLOYMENT_TARGET=10.9 -GXcode ../
popd