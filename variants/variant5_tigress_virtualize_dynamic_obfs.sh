tigress --Seed=0 --Statistics=0 --Verbosity=0 --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=InitEntropy \
        --Functions=init_tigress \
        --InitEntropyKinds=vars \
     --Transform=InitOpaque \
        --Functions=init_tigress \
        --InitOpaqueStructs=list,array,env  \
     --Transform=Virtualize \
        --Skip=false \
        --VirtualizeDispatch=direct \
        --Functions=aes128_enc_wb_final \
     --Transform=JitDynamic \
        --Skip=false \
        --Functions=aes128_enc_wb_final \
        --JitDynamicCodecs=xtea \
        --JitDynamicBlockFraction=%100 \
     --Transform=Measure \
        --Functions=aes128_enc_wb_final \
        --MeasureTimes=100 \
./CHOWAES-JIT.c --out=./out/variant5_CHOWAES_OFS.c
