#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=shiftRows,aes_128_table_encrypt,aes_128_encrypt,mixColumns,expandKey \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=shiftRows,aes_128_table_encrypt,aes_128_encrypt,mixColumns,expandKey \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=shiftRows,aes_128_table_encrypt,aes_128_encrypt,mixColumns,expandKey \
    --Transform=Split \
       --SplitCount=1 \
       --Functions=aes_128_table_encrypt \
./WhiteBoxAES.c --out=./out/test_WhiteBoxAES_1_variant.c
