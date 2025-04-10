# Copyright (c) 2022 Intel Corporation
# Copyright (c) 2020-2021 Alibaba Cloud
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if (BUILD_LATTE_TEE STREQUAL "SGX")
  add_definitions(-DBUILD_LATTE_SGX=1)
  if (NOT DEFINED ENV{SGX_SDK})
    message(FATAL_ERROR "Environment variable SGX_SDK not found!")
  endif()
  include_directories($ENV{SGX_SDK}/include)
  link_directories($ENV{SGX_SDK}/lib64)
  link_libraries(sgx_wasm)
elseif (BUILD_LATTE_TEE STREQUAL "PENGLAI")
  add_definitions(-DBUILD_LATTE_PENGLAI=1)
else ()
  message(WARNING "TARGET TEE <${BUILD_LATTE_TEE}> not supported!")
endif ()

set (LATTE_DIR /home/jiax/Desktop/wasm_workspace/portmr)
include_directories(${LATTE_DIR}/lib)
link_directories(${LATTE_DIR}/tools/gen_extension_sec/build)
link_libraries(latte)

set (LIB_LATTE_DIR ${CMAKE_CURRENT_LIST_DIR})
include_directories(${LIB_LATTE_DIR})

set (LIB_LATTE_SOURCE 
    ${LIB_LATTE_DIR}/lib_latte_wrapper.c)
