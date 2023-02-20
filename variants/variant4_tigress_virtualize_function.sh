#!/bin/bash
tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
      --Functions=aes128_enc_wb_final \
      --VirtualizeDispatch=direct \
./CHOWAES.c --out=./out/variant4_CHOWAES_OFS.c
