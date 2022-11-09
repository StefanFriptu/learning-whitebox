#!/bin/bash
if [ -d "out" ];
then
    echo "Build directory exists."
else
    echo "Creating build directory.."
    mkdir out
fi

echo "Running obfuscator script.."
./variants/variant1_opaque_encmath_aa_split.sh
echo "Entering directory 'out'.."
cd out
echo "Bulding variant.."
gcc -o variant1 variant1_CHOWAES_OFS.c

if [ $# -eq 1 ]
then
    if [ $1 = "--no-symbols" ]
    then
        echo "Removing debug symbols.."
        strip variant1
    fi
fi

echo "Exitting build directory.."
cd ..
echo "Done!"
