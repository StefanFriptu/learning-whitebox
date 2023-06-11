#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=bs_wbsr,wbaes,bs_wbsbox,bs_wbmc \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=bs_wbsr,wbaes,bs_wbsbox,bs_wbmc \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=bs_wbsr,wbaes,bs_wbsbox,bs_wbmc \
    --Transform=Split \
       --SplitCount=1 \
       --Functions=wbaes \
./BU-White-box-AES.c --out=./out/test_BUWhiteBoxAes_variant.c
