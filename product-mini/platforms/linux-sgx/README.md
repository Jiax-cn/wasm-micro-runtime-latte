### build

```bash
export LATTE_DIR=xxx
mkdir build && cd build
cmake .. -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1 -DBUILD_LATTE_TEE=SGX -DLATTE_DIR=$LATTE_DIR && make -j

# prepare runtime_common.bin
cd latte-trainer && make gen_rt_mr
$LATTE_DIR/tools/generate_runtime_common/build/generate_runtime_common xxx && cp runtime_common.bin ./

# prepare trainer_latte.wasm and runner_latte.wasm
$LATTE_DIR/tools/insert_wasm_latte/build/insert_wasm_latte trainer.wasm runner.wasm
# prepare trainer_latte.wasm.id and runner_latte.wasm.id
$LATTE_DIR/tools/verify_portable_identity/build/verify_portable_identity trainer_latte.wasm runner_latte.wasm

# build enclave
make -j
```
