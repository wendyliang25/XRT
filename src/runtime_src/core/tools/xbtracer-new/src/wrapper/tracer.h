// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef tracer_h
#define tracer_h

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <vector>

#include <google/protobuf/timestamp.pb.h>
#include <func.pb.h>
#include <common/trace_utils.h>

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
    bool ret = msg.SerializeToOstream(&tracer_ofile);
    tracer_ofile.flush();
    return ret;
  }

  bool
  trace_pid(uint32_t pid);

  bool
  remove_trace_pid(uint32_t pid);

  bool
  is_pid_traced(uint32_t pid);

  static
  tracer*
  get_instance();

private:
  static std::unique_ptr<tracer> instance;
  static std::once_flag init_instance_flag;
  std::fstream tracer_ofile;
  level tlevel;
  lib_handle_type coreutil_lib_h;
  std::vector<uint32_t> trace_pids;
  std::mutex pids_mlock;
}; // class xrt::tools::xbracer::tracer

} // namespace xrt::tools::xbtracer

template <typename protobuf_msg>
bool
xbtracer_write_protobuf_msg(const protobuf_msg& msg, bool need_trace)
{
  if (!need_trace)
  {
    return true;
  }
  return xrt::tools::xbtracer::tracer::get_instance()->write_protobuf_msg(msg);
}

void*
xbtracer_get_original_func_addr(const char* symbol);

bool
xbtracer_needs_trace_func(void);

bool
xbtrace_trace_current_func(void);

void
xbtrace_untrace_current_func(void);

template <typename T, typename PFUNC>
void
xbtracer_trace_class_pimpl(T* cobj, PFUNC& func_msg)
{
  // all classes we trace has pimpl handle or similar
  // the pointer of the handle will be used as an ID of the object
  auto this_pimpl = cobj->get_handle();
  void* this_pimpl_ptr = reinterpret_cast<void*>(this_pimpl.get());
  xbtracer_proto::Arg* arg = func_msg.add_arg();
  arg->set_name("pimpl");
  arg->set_type("void*");
  arg->set_size(static_cast<uint32_t>(sizeof(void*) & 0xFFFFFFFFU));
  arg->set_value(std::string(reinterpret_cast<const char*>(&this_pimpl_ptr), sizeof(this_pimpl_ptr)));
}

template <typename PFUNC, typename PFUNC_TRACE_TYPE>
void
xbrtracer_init_func_proto_msg(PFUNC& func_msg, const char* func_name, PFUNC_TRACE_TYPE func_trace_type)
{
  func_msg.set_name(func_name);
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);

  google::protobuf::Timestamp* ts = func_msg.mutable_timestamp();
  ts->set_seconds(seconds.count());
  ts->set_nanos(micros.count() * 1000); // Convert microseconds to nanoseconds

  uint32_t pid = getpid_current_os();
  func_msg.set_pid(pid);
  func_msg.set_status(func_trace_type);
}

template <typename PFUNC>
bool
xbtracer_init_func_entry(PFUNC& func_msg, bool& need_trace, const char* func_s,
                         proc_addr_type& paddr_ptr)
{
  const char* func_mname = get_func_mname_from_signature(func_s);
  if (!func_mname)
  {
    xbtracer_pcritical("failed to get mangled name for function\"", std::string(func_s), "\".");
  }
  paddr_ptr = xbtracer_get_original_func_addr(func_mname);
  if (!paddr_ptr)
  {
    xbtracer_pcritical("failed to get function\"", std::string(func_s), "\", \"", std::string(func_s), "\".");
  }

  if (!xbtracer_needs_trace_func())
  {
    // if function doesn't need to be traced, do not initialize protobuf message
    // this is the case that the function is called from the library.
    xbtracer_pdebug("internal call to \"", std::string(func_s), "\", not tracing.");
    need_trace = false;
    return true;
  }

  xbtrace_trace_current_func();
  xbrtracer_init_func_proto_msg(func_msg, func_s, xbtracer_proto::Func_FuncStatus_FUNC_ENTRY);
  need_trace = true;
  return true;
}

template <typename PFUNC>
bool
xbtracer_init_func_exit(PFUNC& func_msg, bool need_trace, const char* func_s)
{
  if (!need_trace)
  {
    return true;
  }
  xbtrace_untrace_current_func();
  xbrtracer_init_func_proto_msg(func_msg, func_s, xbtracer_proto::Func_FuncStatus_FUNC_EXIT);
  return true;
}

template <typename PFUNC, typename T>
bool
xbrracer_init_member_func_entry(T* cobj, PFUNC& func_msg, bool& need_trace, const char* func_s,
                                proc_addr_type& paddr_ptr)
{
  bool ret = xbtracer_init_func_entry(func_msg, need_trace, func_s, paddr_ptr);
  if (need_trace)
  {
    // trace object handle pointer (pimpl) for member function
    xbtracer_trace_class_pimpl(cobj, func_msg);
  }
  return ret;
}

template <typename PFUNC, typename T>
bool
xbrracer_init_member_func_exit(T* cobj, PFUNC& func_msg, bool& need_trace, const char* func_s)
{
  bool ret = xbtracer_init_func_exit(func_msg, need_trace, func_s);
  if (need_trace)
  {
    // trace object handle pointer (pimpl) for member function
    xbtracer_trace_class_pimpl(cobj, func_msg);
  }
  return ret;
}

#endif // tracer_h
