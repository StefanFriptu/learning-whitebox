#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=aes_main,aes_encrypt,galois_multiplication \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=galois_multiplication,mixColumns \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=aes_encrypt,aes_main \
    --Transform=Split \
       --SplitCount=1 \
       --Functions=aes_main \
./AES.c --out=./out/test_AES_variant.c
