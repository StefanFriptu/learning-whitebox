#!/bin/bash
if [ -d "out" ];
then
    echo "Build directory exists."
else
    echo "Creating build directory.."
    mkdir out
fi

echo "Building unobfuscated variant0.."
gcc -o out/variant0 CHOWAES.c

echo "Running obfuscator script for variant1.."
./variants/variant1_opaque_encmath_aa_split.sh
echo "vairant2.............."
./variants/variant3_tigress_encode_data.sh
echo "vairant3.............."
./variants/variant4_tigress_virtualize_function.sh

cd out
echo "Building variant1.."
gcc -o variant1 variant1_CHOWAES_OFS.c

echo "Building variant3.."
gcc -o variant3 variant3_CHOWAES_OFS.c

echo "Building variant4.."
gcc -o variant4 variant4_CHOWAES_OFS.c

cd ..
echo "Building variant2.."
./variants/variant2_llvm_obfuscator.sh


remove_symbols() {
    cd out
    echo "Removing debug symbols.."
    strip variant1
    strip variant2
    strip variant3
    strip variant4
    cd ..
}

if [ $# -eq 1 ]
then
    if [ $1 -ne "--add-symbols" ]
    then
        remove_symbols
    fi
else
    remove_symbols
fi

echo "Done!"
