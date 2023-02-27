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

cd out
echo "Building variant1.."
gcc -o variant1 variant1_CHOWAES_OFS.c
cd ..
echo "Building variant2.."
./variants/variant2_llvm_obfuscator.sh

remove_symbols() {
    cd out
    echo "Removing debug symbols.."
    strip variant1
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
