// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <version.h>
#include "func.pb.h"

#include <wrapper/tracer.h>
#include <common/trace_utils.h>

namespace xrt::tools::xbtracer
{

  tracer::tracer(const std::string& outf, tracer::level tl) :
	 tracer_ofile(outf, std::ios::out | std::ios::binary | std::ios::trunc),
         tlevel(tl)
  {
    if (!tracer_ofile || !tracer_ofile.is_open())
    {
      throw std::runtime_error("xbtracer failed to open output file: \"" + std::string(outf) + "\".");
    }
    coreutil_lib_h = load_library_os(XBRACER_XRT_COREUTIL_LIB);
    if (!coreutil_lib_h)
    {
      throw std::runtime_error("xbrtracer failer to open lib: \"" +
                               std::string(XBRACER_XRT_COREUTIL_LIB) + "\".");
    }
  }

  tracer::~tracer()
  {
    if (coreutil_lib_h)
    {
      close_library_os(coreutil_lib_h);
    }
    if (tracer_ofile.is_open())
    {
      tracer_ofile.close();
    }
  }

  proc_addr_type
  tracer::get_proc_addr(const char* symbol)
  {
    return get_proc_addr_os(coreutil_lib_h, symbol);
  }

  bool
  tracer::trace_pid(uint32_t pid)
  {
    std::lock_guard<std::mutex> lock(pids_mlock);
    trace_pids.push_back(pid);
    return true;
  }

  bool
  tracer::remove_trace_pid(uint32_t pid)
  {
    std::lock_guard<std::mutex> lock(pids_mlock);
    auto is_matched = [pid](uint32_t _pid) { return pid == _pid; };
    auto it = std::remove_if(trace_pids.begin(), trace_pids.end(), is_matched);
    if (it != trace_pids.end()) {
      trace_pids.erase(it, trace_pids.end());
      return true;
    }
    return false;
  }

  bool
  tracer::is_pid_traced(uint32_t pid)
  {
    std::lock_guard<std::mutex> lock(pids_mlock);
    auto is_matched = [pid](uint32_t _pid) { return pid == _pid; };
    auto it = std::remove_if(trace_pids.begin(), trace_pids.end(), is_matched);
    if (it != trace_pids.end()) {
      return true;
    }
    return false;
  }

  tracer*
  tracer::get_instance()
  {
    std::call_once(init_instance_flag, []()
    {
      // Create a tracer
      // Get environment variable to get the path and the tracing level
      char tlevel[16] = {0};
      char odir[2048] = {0};
      getenv_os("XBTRACER_OUT_DIR", odir, sizeof(odir));
      getenv_os("XBRACER_TRACE_LEVEL", tlevel, sizeof(tlevel));
      tracer::level l = tracer::level::DEFAULT;

      if (strlen(tlevel))
      {
	// TODO: we only support DEFAULT tracing level for now.
	std::string tlevel_str = tlevel;
        if (tlevel_str != "DEFAULT")
	{
          throw std::runtime_error("xbtracer: unsupported tracing level: \"" + tlevel_str + "\".");
	}
      }

      std::filesystem::path opath;
      if (!strlen(odir))
      {
        opath = std::filesystem::current_path();
      }
      else
      {
        opath = odir;
      }
      auto pid = getpid_current_os();
      opath.append(std::string("trace_protobuf" + std::to_string(pid) + ".bin"));
      // convert path to string first before converting it to c string to
      // make it work for both Linux and Windows.
      instance = std::unique_ptr<tracer>(new tracer(opath.string(), l));

      // Log XRT version
      GOOGLE_PROTOBUF_VERIFY_VERSION;
      xbtracer_proto::XrtExportApiCapture msg;
      msg.set_version(XRT_DRIVER_VERSION);
      if (!instance->write_protobuf_msg(msg)) {
        xbtracer_pcritical("get tracer instance failed, failed to log version information.");
      }
    });
    return instance.get();
  }
} // namespace xrt::tools::xbtracer

std::unique_ptr<xrt::tools::xbtracer::tracer> xrt::tools::xbtracer::tracer::instance = nullptr;
std::once_flag xrt::tools::xbtracer::tracer::init_instance_flag;

void*
xbtracer_get_original_func_addr(const char*symbol)
{
  xrt::tools::xbtracer::tracer* tracer = xrt::tools::xbtracer::tracer::get_instance();
  return tracer->get_proc_addr(symbol);
}

bool
xbtracer_needs_trace_func(void)
{
  uint32_t pid = getpid_current_os();
  xrt::tools::xbtracer::tracer* tracer = xrt::tools::xbtracer::tracer::get_instance();
  return !tracer->is_pid_traced(pid);
}

bool
xbtrace_trace_current_func(void)
{
  uint32_t pid = getpid_current_os();
  xrt::tools::xbtracer::tracer* tracer = xrt::tools::xbtracer::tracer::get_instance();
  return tracer->trace_pid(pid);
}

void
xbtrace_untrace_current_func(void)
{
  uint32_t pid = getpid_current_os();
  xrt::tools::xbtracer::tracer* tracer = xrt::tools::xbtracer::tracer::get_instance();
  tracer->remove_trace_pid(pid);
}
