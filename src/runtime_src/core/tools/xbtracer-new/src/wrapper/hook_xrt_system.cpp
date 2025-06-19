#include <wrapper/hook_xrt.h>

unsigned int
xrt::system::
enumerate_devices()
{
  const char* func_s = "xrt::system::enumerate_devices(void)";
  typedef unsigned int (*func_t)(void);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  unsigned int ret_o = ofunc();

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}
