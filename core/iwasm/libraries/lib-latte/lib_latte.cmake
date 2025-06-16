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

if(NOT DEFINED LATTE_DIR) 
  message(FATAL_ERROR "LATTE_DIR should be specified!")
endif()
include(${LATTE_DIR}/src/lib_latte.cmake)
link_libraries(latte)

set (LIB_LATTE_DIR ${CMAKE_CURRENT_LIST_DIR})
include_directories(${LIB_LATTE_DIR})

set (LIB_LATTE_SOURCE 
    ${LIB_LATTE_DIR}/lib_latte_wrapper.c)
