// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef trace_utils_h
#define trace_utils_h

#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <typeinfo>
#include "common/trace_logger.h"

#ifdef _WIN32
#define XBRACER_XRT_COREUTIL_LIB "xrt_coreutil.dll"
#else
#define XBRACER_XRT_COREUTIL_LIB "libxrt_coreutil.so.2"
#endif

extern "C" const char* func_mangled_map[];

int
setenv_os(const char* name, const char* val);

int
getenv_os(const char* name, char* buf, uint32_t len);

int
localtime_os(std::tm& tm, const std::time_t& t);

size_t
get_size_of_func_mangled_map(void);

const char*
get_func_mname_from_signature(const char* s);

#endif // trace_utils_h
