#!/bin/bash

cd ../build && make && cd ../latte-trainer

make gen_rt_mr && cp ./sgx_rt_mr.bin /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder

pushd /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder

rm -f ./latte_runner.wasm

rm -f ./latte_trainer.wasm

./latte_builder trainer.wasm runner.wasm

popd

cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/latte_trainer.wasm ./
cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/trainer.wasm.id ./
cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/runtime_common.bin ./

make