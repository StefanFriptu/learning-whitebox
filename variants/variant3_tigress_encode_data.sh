#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=EncodeData \
      --GlobalVariables='Tboxes,Txor,Ty,Tyboxes' \
      --EncodeDataCodecs=poly1 \
./CHOWAES.c --out=./out/variant3_CHOWAES_OFS.c
