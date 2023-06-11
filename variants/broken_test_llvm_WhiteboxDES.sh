#!/bin/bash

make_binary() {
    $CC -std=c99 -g -O2 WhiteboxDES.c -mllvm -obfuscate="rounds" -lm
    mv a.out ./out/test_WhiteboxDES_llvm
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
