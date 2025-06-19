#include <wrapper/hook_xrt.h>

std::string
xrt::error::
to_string() const
{
  const char* func_s = "xrt::error::to_string(void)";
  typedef std::string (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  std::string ret_o = ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}

xrt::error::
error(const xrt::device& device, xrtErrorClass ecl)
{
  const char* func_s = "xrt::error::error(const xrt::device&, xrtErrorClass)";
  typedef xrt::error* (*func_t)(void*, const xrt::device&, xrtErrorClass);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, ecl);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::error::
error(xrtErrorCode ecl, xrtErrorTime timestamp)
{
  const char* func_s = "xrt::error::error(xrtErrorCode, xrtErrorTime)";
  typedef xrt::error* (*func_t)(void*, xrtErrorCode, xrtErrorTime);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, ecl, timestamp);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrtErrorCode
xrt::error::
get_error_code() const
{
  const char* func_s = "xrt::error::get_error_code(void)";
  typedef xrtErrorCode (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  xrtErrorCode ret_o = ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}

xrtErrorTime
xrt::error::
get_timestamp() const
{
  const char* func_s = "xrt::error::get_timestamp(void)";
  typedef xrtErrorTime (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  xrtErrorTime ret_o = ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}
