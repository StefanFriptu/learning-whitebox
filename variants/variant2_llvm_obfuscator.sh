#!/bin/bash

make_binary() {
    $CC -O2 CHOWAES.c -mllvm -obfuscate="aes128_enc_wb_final"
    mv a.out ./out/variant2
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
