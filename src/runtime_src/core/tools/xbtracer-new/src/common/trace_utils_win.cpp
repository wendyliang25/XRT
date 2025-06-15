// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifdef _WIN32

#include <cerrno>
#include <stdlib.h>
#include <common/trace_utils.h>
#include "core/common/windows/win_utils.h"
#include <windows.h>
#include <tlhelp32.h>

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

int
localtime_os(std::tm& tm, const std::time_t& t)
{
  return static_cast<int>(localtime_s(&tm, &t));
}

uint32_t
getpid_current_os(void)
{
    DWORD pid = GetCurrentProcessId();
    return static_cast<uint32_t>(pid & 0xFFFFFFFFU);
}

int
inject_library(HANDLE hprocess, const char* lib_path)
{
  // Get the address of LoadLibraryA in kernel32.dll
  HMODULE hkernel32 = GetModuleHandle("kernel32.dll");
  if (!hkernel32)
  {
    xbtracer_pcritical("inject \"", std::string(lib_path),
                       "\" failed, failed to get handle to kernel32.dll.");
  }

  FARPROC load_lib_addr = GetProcAddress(hkernel32, "LoadLibraryA");
  if (!load_lib_addr)
  {
    xbtracer_pcritical("inject \"", std::string(lib_path),
                       "\" failed, failed to get address of LoadLibraryA.");
  }

  // Allocate memory in the target process for the library path
  void* remote_mem = VirtualAllocEx(hprocess, nullptr, strlen(lib_path) + 1,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote_mem)
  {
    xbtracer_pcritical("inject \"", std::string(lib_path),
                       "\" failed, failed to allocate memory in target process.");
  }

  // Write the library path to the allocated memory
  if (!WriteProcessMemory(hprocess, remote_mem, lib_path, strlen(lib_path) + 1, nullptr))
  {
    VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
    xbtracer_pcritical("inject \"", std::string(lib_path),
                        "\" failed, failed to write library path to target process memory.");
  }

  // Create a remote thread in the target process to load the library
  HANDLE hthread = CreateRemoteThread(hprocess, nullptr, 0, (LPTHREAD_START_ROUTINE)load_lib_addr,
                                      remote_mem, 0, nullptr);
  if (!hthread)
  {
    VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
    xbtracer_pcritical("inject \"", std::string(lib_path),
                       "\" failed, failed to create remote thread in target process,",
                       sys_dep_get_last_err_msg(), ".");
  }

  // Wait for the remote thread to finish
  WaitForSingleObject(hthread, INFINITE);

  // Clean up
  CloseHandle(hthread);
  VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);

  return 0;
}

#endif // _WIN32
