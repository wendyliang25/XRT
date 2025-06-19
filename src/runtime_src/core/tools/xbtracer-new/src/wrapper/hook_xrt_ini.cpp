#include <wrapper/hook_xrt.h>

void
xrt::ini::
set(const std::string& key, const std::string& value)
{
  const char* func_s = "xrt::ini::set(const std::string&, const std::string&)";
  typedef void (*func_t)(const std::string&, const std::string&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc(key, value);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
