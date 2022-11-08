#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
      --Functions=init_tigress \
      --InitEntropyKinds=vars \
    --Transform=InitOpaque \
      --Functions=init_tigress \
      --InitOpaqueStructs=list,array,env \
    --Transform=AddOpaque \
      --Functions=ShiftRows,aes128_enc_wb_final \
      --AddOpaqueStructs=list \
      --AddOpaqueKinds=true \
    --Transform=EncodeArithmetic \
      --Functions=aes128_enc_wb_final,ShiftRows \
      --EncodeArithmeticKinds=integer \
    --Transform=AntiAliasAnalysis \
      --Functions=aes128_enc_wb_final,ShiftRows \
    --Transform=Split \
       --SplitCount=10 \
       --Functions=aes128_enc_wb_final \
CHOWAES.c --out=CHOWAES_OFS.c

