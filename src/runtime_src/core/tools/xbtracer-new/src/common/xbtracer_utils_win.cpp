// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <string>
#include <windows.h>
#include "core/common/linux/linux_utils.h"
#include "common/utils.h"

int copy_libs_to_temp(std::string &temp_path,
                      const std::vector<std::tuple<std::string, std::string>> &libs)
{
  char tmp_path[MAX_PATH];
  if (!GetTempPath(MAX_PATH, tmp_path)) {
    tracer_print_e("Failed to get temporary path, " + get_sys_last_err_msg());
    return -1;
  }
  std::string tmp_dir = std::string(tmp_path) + "\\tmp_xbtracer\\";
  if (!CreateDirectory(tmp_dir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
    tracer_print_e("Unable to create temporary directory" + get_sys_last_err_msg());;
    return -1;
  }
  HMODULE lib_hd;
  for (const auto &e : libs) {
    std::string org_lib, new_lib;
    std::tie(org_lib, new_lib) = e;
    lib_hd = LoadLibrary((LPCSTR)org_lib.c_str());
    if (!lib_hd) {
      tracer_print_e("Failed to load library " + org_lib + ", " + get_sys_last_err_msg());
      return -1;
    }
    char lib_path[MAX_PATH];
    if (!GetModuleFileName(lib_hd, lib_path, sizeof(lib_path))) {
      tracer_print_e("Failed to get library " + org_lib + " path, " + get_sys_last_err_msg());
      goto err_free_org_lib;
    }
    FreeLibrary(lib_hd);
    std::string new_lib_path = tmp_dir + new_lib;
    if (!CopyFile(lib_path, new_lib_path, FALSE) {
      tracer_print_e("Failed to copy " + lib_path + " to " + new_lib_path + ".");
      goto err_free_org_lib;
    }
  }

  return 0;
err_free_org_lib:
  FreeLibrary(lib_hd);
  return -1;
}

int inject_library(HANDLE hprocess, const char* lib_path) {
  // Allocate memory in the target process for the library path
  void* remote_mem = VirtualAllocEx(hprocess, nullptr, strlen(lib_path) + 1,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote_mem) {
      tracer_print_e("Failed to allocate memory in target process.");
      return -1;
  }

  // Write the library path to the allocated memory
  if (!WriteProcessMemory(hprocess, remote_mem, lib_path, strlen(lib_path) + 1, nullptr)) {
      tracer_print_e("Failed to write library path to target process memory.");
      VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
      return -1;
  }

  // Get the address of LoadLibraryA in kernel32.dll
  HMODULE hkernel32 = GetModuleHandle("kernel32.dll");
  if (!hkernel32) {
      tracer_print_e("Failed to get handle to kernel32.dll.");
      VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
      return -1;
  }

  FARPROC load_lib_addr = GetProcAddress(hkernel32, "LoadLibraryA");
  if (!load_lib_addr) {
      tracer_print_e("Failed to get address of LoadLibraryA.");
      VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
      return -1;
  }

  // Create a remote thread in the target process to load the library
  HANDLE hthread = CreateRemoteThread(hprocess, nullptr, 0, (LPTHREAD_START_ROUTINE)load_lib_addr, remote_mem, 0, nullptr);
  if (!hthread) {
      tracer_print_e("Failed to create remote thread in target process.");
      VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);
      return -1;
  }

  // Wait for the remote thread to finish
  WaitForSingleObject(hthread, INFINITE);

  // Clean up
  CloseHandle(hthread);
  VirtualFreeEx(hprocess, remote_mem, 0, MEM_RELEASE);

  return true;
}
