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

# Build binaries
cd out
echo "Building variant1.."
gcc -o variant1 variant1_CHOWAES_OFS.c

cd ..
echo "Building variant2.."
./variants/variant2_llvm_obfuscator.sh

cd out
echo "Building variant3.."
gcc -o variant3 variant3_CHOWAES_OFS.c

echo "Building variant4.."
gcc -o variant4 variant4_CHOWAES_OFS.c

echo "Building variant5.."
gcc -o variant5 variant5_CHOWAES_OFS.c

echo "Building variant6.."
gcc -o variant6 variant6_CHOWAES_OFS.c

echo "Building variant7.."
gcc -o variant7 variant7_CHOWAES_OFS.c

echo "Building test variant - WhiteBoxAES.."
gcc -o test_WhiteBoxAES_1_variant test_WhiteBoxAES_1_variant.c

echo "Building test variant - BU-Whitebox-Aes Tigress.."
gcc -o test_BUWhiteBoxAes_variant test_BUWhiteBoxAes_variant.c

cd ..
echo "Building test variant - WhiteBoxAES LLVM obfuscation.."
./variants/test_llvm_WhiteBoxAES.sh

echo "Building test variant - BU-Whitebox-Aes LLVM obfuscation.."
./variants/test_llvm_BUWhiteBoxAES.sh


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
