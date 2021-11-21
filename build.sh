#!/bin/bash
rm -r _build
mkdir _build
cd _build
cmake  -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=/home/voev/Sources/_ossl_build -DOPENSSL_INCLUDE_DIR=/home/voev/Sources/_ossl_build/include -DOPENSSL_LIBRARIES=/home/voev/Sources/_ossl_build/lib ..
make 


