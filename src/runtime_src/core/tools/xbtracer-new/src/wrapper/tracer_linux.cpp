// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifdef __linux__
#include <common/trace_utils.h>

proc_addr_type
xbtracer_get_original_func_addr(const char* symbol)
{
  xrt::tools::xbtracer::tracer* tracer = xrt::tools::xbtracer::tracer::get_instance();
  return tracer->get_proc_addr(symbol);
}

#endif // __linux__
