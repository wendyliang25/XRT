// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifdef __linux__

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdlib.h>
#include <common/trace_utils.h>

int
setenv_os(const char* name, const char* val)
{
  return setenv(name, val, 1);
}

int
getenv_os(const char* name, char* buf, uint32_t len)
{
  const char *tmpstr = getenv(name);

  if (!tmpstr)
  {
    return 0;
  }

  size_t env_len = strlen(tmpstr);
  if ((len + 1) < env_len)
  {
    return -EINVAL;
  }
  strcpy(buf, tmpstr);

  return env_len;
}

#endif // __linux__
