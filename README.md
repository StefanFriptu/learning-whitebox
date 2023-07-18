# learning-whitebox

The repository contains the code described in my master's thesis "Learning white-box: Applying machine learning to identify white-box related functions in binaries" which can be found on TU/e website. The `belaida` script loads a trained SVM model and classifies whether functions in a binary are white-box related or not (see paper). It's a proof of concept!

The repository was initially thought to create scripts that obfuscate Chow's white-box implementation. However, it ended up containing source code from multiple repositories, which were needed to create obfuscated variants. Some files were merged into one source file. The ownerships are as following:
* `AES.c`: [m3y54m/aes-in-c](https://github.com/m3y54m/aes-in-c)
* `DES.c`: [mimoo/DES](https://github.com/mimoo/DES)
* `WhiteBoxAES.c` and other files: [Gr1zz/WhiteBoxAES](https://github.com/Gr1zz/WhiteBoxAES)
* `WhiteboxDES.c` and other files: [mimoo/whiteboxDES](https://github.com/mimoo/whiteboxDES)
* `BU-White-box-AES.c` and others: [Nexus-TYF/BU-White-box-AES](https://github.com/Nexus-TYF/BU-White-box-AES)
* Chow's basic implementation and tables: [Spotlight on an unprotected AES128 white-box implementation](https://doar-e.github.io/blog/2015/02/08/spotlight-on-an-unprotected-aes128-whitebox-implementation/)

Pre-requisites:
* gcc
* Tigress
* [LLVM based obfuscator](https://github.com/Deniskore/llvm)

Building with debug symbols:
```
./build-variants.sh
```

If you want to add debug symbols for the binaries, add the `--add-symbols` argument when running the build script. The llvm-obfuscated binary will not include symbols.

Other files:
* `belaida.py`: script which can run in IDA Pro 8.0+ to classify white-box related functions in a binary
* `rebel-ida.py`: used to extract features from samples. Runs in IDA Pro 8.0
* `classifier-hyperparameter-tuning.py`: exactly what the name says
* `variants/*.sh`: scripts used to create obfuscated variants of the implementations mentioned above
* `*.pkl` files: trained SVM model in pickle format
