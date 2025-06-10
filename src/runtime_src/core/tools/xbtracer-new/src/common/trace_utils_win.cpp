// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifdef _WIN32

#include <cerrno>
#include <stdlib.h>
#include <common/trace_utils.h>
#include <windows.h>

int
setenv_os(const char* name, const char* val)
{
  if (SetEnvironmentVariable(name, val))
  {
    return 0;
  }
  return -EINVAL;
}

int
getenv_os(const char* name, char *buf, uint32_t len)
{
  DWORD rlen = GetEnvironmentVariable(name, buf, len);
  if (rlen > (DWORD)len)
  {
    buf[0] = 0;
    return -EINVAL;
  }
  return static_cast<int>(rlen & 0xFFFFFFFFU);
}

#endif // _WIN32
