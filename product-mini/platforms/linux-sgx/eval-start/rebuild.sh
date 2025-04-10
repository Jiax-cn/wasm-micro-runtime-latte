#!/bin/bash

cd ../build && make && cd ../eval-start

make gen_rt_mr && cp ./sgx_rt_mr.bin /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder

pushd /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder

rm -f ./latte_helloworld.wasm

./latte_builder helloworld.wasm helloworld.wasm

popd

cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/latte_helloworld.wasm ./
cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/helloworld.wasm.id ./
cp /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/runtime_common.bin ./

make