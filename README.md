## IMWS

## Build

This project depends on [pailliercryptolib](https://github.com/intel/pailliercryptolib) and `libOTe`. The author used `gcc 12.2.0`.

```shell
cd libOTe
python build.py --all --boost --sodium
cd .. 
mkdir build
cd build
cmake ..
make -j
```

## Contact

Contact `lzjluzijie@gmail.com` if you have any question.
