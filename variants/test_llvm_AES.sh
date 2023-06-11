#!/bin/bash

make_binary() {
    $CC -O2 AES.c -mllvm -obfuscate="aes_main,aes_encrypt"
    mv a.out ./out/test_AES_llvm
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
