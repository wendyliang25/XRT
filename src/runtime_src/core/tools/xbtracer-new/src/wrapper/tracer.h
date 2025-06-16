// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef tracer_h
#define tracer_h

#include <fstream>
#include <iostream>
#include <mutex>

#include <common/trace_utils.h>

extern "C" const char* func_mangled_map[];

namespace xrt::tools::xbtracer
{

class tracer
{
  enum class level
  {
    DEFAULT = 0,
  };

public:
  tracer(const std::string& outf, level tl);

  // we always need to output tracing to a file
  tracer() = delete;
  // delete copy constructor and assignment operator to enforce singleton
  tracer(const tracer&) = delete;
  tracer& operator=(const tracer&) = delete;

  ~tracer();

  proc_addr_type
  get_proc_addr(const char* symbol);

  template <typename protobuf_msg>
  bool
  write_protobuf_msg(const protobuf_msg& msg)
  {
    return msg.SerializeToOstream(&tracer_ofile);
  }

  static
  tracer*
  get_instance();

private:
  static std::unique_ptr<tracer> instance;
  static std::once_flag init_instance_flag;
  std::fstream tracer_ofile;
  level tlevel;
  lib_handle_type coreutil_lib_h;
}; // class xrt::tools::xbracer::tracer

} // namespace xrt::tools::xbtracer

template <typename protobuf_msg>
bool
xbtracer_write_protobuf_msg(const protobuf_msg& msg)
{
  return xrt::tools::xbtracer::tracer::get_instance()->write_protobuf_msg(msg);
}

void*
xbtracer_get_original_func_addr(const char* symbol);
#endif // tracer_h
