# env

Penglai qemu with toolchain under "/home/penglai/penglai-multilib-toolchain-install/bin/"

* mkdir build && cd build
* cmake .. -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1  -DBUILD_LATTE_TEE=PENGLAI && make
