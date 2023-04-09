tigress --Seed=42 --Statistics=0 --Verbosity=1 --Environment=x86_64:Darwin:Clang:5.1  \
     --Transform=InitEntropy \
        --Functions=init_tigress \
        --InitEntropyKinds=vars \
     --Transform=InitOpaque \
        --Functions=init_tigress \
        --InitOpaqueStructs=list,array,env  \
     --Transform=Merge \
        --MergeFlatten=false \
        --MergeName=MERGED \
        --Functions=aes128_enc_wb_final,ShiftRows,init_tigress \
     --Transform=Virtualize \
        --VirtualizeDispatch=direct \
        --Functions=MERGED \
     --Transform=EncodeLiterals \
        --Functions=main \
./CHOWAES.c --out=./out/variant6_CHOWAES_OFS.c
