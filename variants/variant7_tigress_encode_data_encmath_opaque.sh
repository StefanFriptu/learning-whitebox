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
    --Transform=EncodeData \
      --GlobalVariables='Tboxes,Txor,Ty,Tyboxes' \
      --EncodeDataCodecs=poly1 \
    --Transform=EncodeArithmetic \
      --Functions=aes128_enc_wb_final,ShiftRows \
      --EncodeArithmeticKinds=integer \
./CHOWAES-int-tables.c --out=./out/variant7_CHOWAES_OFS.c
