// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef trace_utils_h
#define trace_utils_h

#include <cstdint>
#include <cstring>
#include <iostream>
#include <typeinfo>
#include "common/trace_logger.h"

int
setenv_os(const char* name, const char* val);

int
getenv_os(const char* name, char* buf, uint32_t len);

#endif // trace_utils_h
