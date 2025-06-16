# env
```bash
export LATTE_DIR=xxx
# /home/penglai/penglai-multilib-toolchain-install/bin/
export MULTILIB_TOOLCHAIN=xxx
# /home/penglai/penglai-enclave/Penglai-sdk-TVM/
export PENGLAI_SDK=xxx

mkdir build && cd build
cmake .. -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1 -DBUILD_LATTE_TEE=PENGLAI -DLATTE_DIR=$LATTE_DIR && make -j

cd wamr-steps && make -j
```
