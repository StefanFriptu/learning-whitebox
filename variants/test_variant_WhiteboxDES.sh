#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=before_rounds,rounds,end_rounds,main \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=before_rounds,rounds,end_rounds \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=before_rounds,rounds,end_rounds \
    --Transform=Split \
       --SplitCount=1 \
       --Functions=rounds \
./WhiteboxDES.c --out=./out/test_WhiteboxDES_variant.c
