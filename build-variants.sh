#!/bin/bash
if [ -d "out" ];
then
    echo "Build directory exists."
else
    echo "Creating build directory.."
    mkdir out
fi

echo "Building simple AES implementation.."
gcc -g AES.c -o out/simpleaes

echo "Building unobfuscated variant0.."
gcc -o out/variant0 CHOWAES.c

# Run Tigress obfuscator scripts
echo "Running obfuscator script for variant1.."
./variants/variant1_opaque_encmath_aa_split.sh
echo "vairant3.............."
./variants/variant3_tigress_encode_data.sh
echo "vairant4.............."
./variants/variant4_tigress_virtualize_function.sh
echo "variant5.............."
./variants/variant5_tigress_virtualize_dynamic_obfs.sh
echo "variant6.............."
./variants/variant6_tigress_merge_virtualize_encodelit.sh
echo "variant7.............."
./variants/variant7_tigress_encode_data_encmath_opaque.sh
echo "test variant - WhiteBoxAES.............."
./variants/test_variant_WhiteBoxAES.sh
echo "test variant - BUWhiteBoxAES............"
./variants/test_variant_BUWhiteBoxAES.sh
echo "test variant - WhiteboxDES.............."
./variants/test_variant_WhiteboxDES.sh
echo "test variant - DES......................"
./variants/test_variant_DES.sh
echo "test variant - AES......................"
./variants/test_variant_AES.sh

# Build binaries
cd out
echo "[Tigress] Building variant1.."
gcc -w -o variant1 variant1_CHOWAES_OFS.c

cd ..
echo "[LLVM] Building variant2.."
./variants/variant2_llvm_obfuscator.sh

cd out
echo "[Tigress] Building variant3.."
gcc -w -o variant3 variant3_CHOWAES_OFS.c

echo "[Tigress] Building variant4.."
gcc -w -o variant4 variant4_CHOWAES_OFS.c

echo "[Tigress] Building variant5.."
gcc -w -o variant5 variant5_CHOWAES_OFS.c

echo "[Tigress] Building variant6.."
gcc -w -o variant6 variant6_CHOWAES_OFS.c

echo "[Tigress] Building variant7.."
gcc -w -o variant7 variant7_CHOWAES_OFS.c

echo "[Tigress] Building test variant - WhiteBoxAES.."
gcc -w -o test_WhiteBoxAES_1_variant test_WhiteBoxAES_1_variant.c

echo "[Tigress] Building test variant - BU-Whitebox-Aes.."
gcc -w -o test_BUWhiteBoxAes_variant test_BUWhiteBoxAes_variant.c

echo "[Tigress] Building test variant - WhiteboxDES.."
gcc -w -o test_WhiteboxDES_variant test_WhiteboxDES_variant.c

echo "[Tigress] Building test variant - DES.."
gcc -w -o test_DES_variant test_DES_variant.c

echo "[Tigress] Building test variant - AES.."
gcc -w -o test_AES_variant test_AES_variant.c

cd ..
echo "[LLVM] Building test variant - WhiteBoxAES LLVM obfuscation.."
./variants/test_llvm_WhiteBoxAES.sh

echo "[LLVM] Building test variant - BU-Whitebox-Aes LLVM obfuscation.."
./variants/test_llvm_BUWhiteBoxAES.sh

# LLVM fails compiling this
# echo "[LLVM] Building test variant - WhiteboxDES LLVM.."
# ./variants/test_llvm_WhiteboxDES.sh

echo "[LLVM] Building test variant - DES LLVM.."
./variants/test_llvm_DES.sh

echo "[LLVM] Building test variant - AES LLVM.."
./variants/test_llvm_AES.sh

remove_symbols() {
    cd out
    echo "Removing debug symbols.."
    strip variant1
    strip variant2
    strip variant3
    strip variant4
    strip variant5
    strip variant6
    strip variant7
    strip test_WhiteBoxAES_1_variant
    strip test_WhiteBoxAES_1_llvm
    strip test_BUWhiteBoxAes_variant
    strip test_BUWhiteBoxAes_llvm
    strip test_WhiteboxDES_variant
    # strip test_WhiteboxDES_llvm
    strip test_DES_variant
    strip test_DES_llvm
    strip test_AES_variant
    strip test_AES_llvm
    cd ..
}

if [ $# -eq 1 ]
then
    if [ $1 != "--add-symbols" ]
    then
        remove_symbols
    fi
else
    remove_symbols
fi

echo "Done!"
