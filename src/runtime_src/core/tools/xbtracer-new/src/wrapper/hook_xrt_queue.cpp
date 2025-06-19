#include <wrapper/hook_xrt.h>

void
xrt::queue::
add_task(xrt::queue::task&& ev)
{
  const char* func_s = "xrt::queue::add_task(xrt::queue::task&&)";
  typedef void (*func_t)(void*, xrt::queue::task&&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry(this->m_impl, func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, std::move(ev));

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit(this->m_impl, func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::queue::
queue()
{
  const char* func_s = "xrt::queue::queue(void)";
  typedef xrt::queue* (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry(this->m_impl, func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit(this->m_impl, func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
