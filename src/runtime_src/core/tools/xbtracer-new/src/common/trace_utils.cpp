// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <cstdint>
#include <cstring>
#include <common/trace_utils.h>

const char*
get_func_mname_from_signature(const char* s)
{
  for (uint32_t i = 0; i < get_size_of_func_mangled_map(); i += 2)
  {
    if (!strcmp(s, func_mangled_map[i]))
    {
      return func_mangled_map[++i];
    }
  }
  return nullptr;
}
