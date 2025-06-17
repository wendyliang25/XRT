// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <wrapper/hook_xrt.h>

xrt::device::
device(unsigned int didx)
{
  xbtracer_pinfo("xrt::device::device.");
  const char* func_s = "xrt::device::device(unsigned int)";
  typedef xrt::device* (*func_t)(void*, unsigned int);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbrracer_init_member_func_entry(this, func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;
  ofunc(this, didx);
  
  xbtracer_proto::Func func_exit;
  xbrracer_init_member_func_exit(this, func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
