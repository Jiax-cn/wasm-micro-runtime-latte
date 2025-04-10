# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_PENGLAI)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

if ("$ENV{PENGLAI_SDK}" STREQUAL "")
  set (PENGLAI_SDK_DIR "/home/penglai/penglai-enclave/Penglai-sdk-TVM/")
else()
  set (PENGLAI_SDK_DIR $ENV{PENGLAI_SDK})
endif()
include_directories (${PENGLAI_SDK_DIR}/lib/app/include)
include_directories(${PENGLAI_SDK_DIR}/lib/wolfssl)
# include_directories (${PENGLAI_SDK_DIR}/musl/include)
# include_directories (${PENGLAI_SDK_DIR}/musl/arch/riscv64)
# include_directories (${PENGLAI_SDK_DIR}/musl/obj/include)

file (GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

set (PLATFORM_SHARED_SOURCE ${source_all})
