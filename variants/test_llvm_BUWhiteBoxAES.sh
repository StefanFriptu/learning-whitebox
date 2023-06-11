#!/bin/bash

make_binary() {
    $CC -O2 BU-White-box-AES.c -mllvm -obfuscate="wbaes"
    mv a.out ./out/test_BUWhiteBoxAes_llvm
}

echo "Searching for clang in ../llvm/build/bin/clang"
CC=./../llvm/build/bin/clang
if ! [[ -f $CC ]];
then
    echo "ERROR: executable not found ../llvm/build/bin/clang"
    exit 1
fi

echo "Found clang binary at $CC"
echo "Building binary..."
make_binary
