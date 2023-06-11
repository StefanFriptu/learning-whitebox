#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=rounds,key_schedule \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=rounds,key_schedule \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=rounds,key_schedule \
    --Transform=Split \
       --SplitCount=1 \
       --Functions=rounds \
./DES.c --out=./out/test_DES_variant.c
