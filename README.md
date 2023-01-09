# hidden-rice

The project scope is to create scripts that obfuscate Chow's white-box implementation.

Pre-requisites:
* gcc
* tigress

Building with debug symbols:
```
./build-variants.sh
```

If you want to add debug symbols for the binaries, add the `--add-symbols` argument when running the build script. The llvm-obfuscated binary will not include symbols.
