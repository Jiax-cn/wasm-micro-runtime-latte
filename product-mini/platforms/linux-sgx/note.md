###

* mkdir build && cd build
* cmake .. -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1 -DBUILD_LATTE_TEE=SGX && make
* verbose: -DCMAKE_VERBOSE_MAKEFILE=ON 
* jit: -DWAMR_BUILD_FAST_JIT=1