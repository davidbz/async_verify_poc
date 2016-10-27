#!/bin/bash
set -e

abort() {
    echo "failed, aborting."
    exit 1
}

mkdir -p build

STAGINGDIR=`pwd`/staging
mkdir -p ${STAGINGDIR}
echo "Using ${STAGINGDIR} as a staging directory."
echo "PREFIX=${STAGINGDIR}" > sample_plugin/config.mk

mkdir -p build
[ -d build/openssl ] || git clone https://github.com/yossigo/openssl -b async_verify build/openssl
[ -d build/trafficserver ] || git clone https://github.com/yossigo/trafficserver -b async_verify build/trafficserver
[ -d build/curl ] || git clone https://github.com/curl/curl -b curl-7_50_3 build/curl

echo "Building OpenSSL, logging to build/openssl.log"
(
pushd build/openssl
./Configure --prefix=${STAGINGDIR} shared linux-x86_64
make clean
make -j
make install
popd
) >build/openssl.log 2>&1 || abort

echo "Building curl, logging to build/curl.log"
(
pushd build/curl
./configure --prefix=${STAGINGDIR} LDFLAGS=-L${STAGINGDIR}/lib CFLAGS=-I${STAGINGDIR}/include
make -j
make install
popd
) >build/curl.log 2>&1 || abort

echo "Building trafficserver, logging to trafficserver.log"
(
pushd build/trafficserver
./configure --prefix=${STAGINGDIR} --with-openssl=${STAGINGDIR} --enable-debug
make -j
make install
popd
) >build/trafficserver.log 2>&1 || abort

