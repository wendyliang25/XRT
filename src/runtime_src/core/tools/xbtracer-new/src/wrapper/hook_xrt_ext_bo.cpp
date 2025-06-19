#include <wrapper/hook_xrt.h>

xrt::ext::bo::
bo(const xrt::device& device, size_t sz)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::device&, size_t)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::device&, size_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, sz);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::device& device, size_t sz, xrt::ext::bo::access_mode access)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::device&, size_t, xrt::ext::bo::access_mode)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::device&, size_t, xrt::ext::bo::access_mode);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, sz, access);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::device& device, void* userptr, size_t sz)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::device&, void*, size_t)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::device&, void*, size_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, userptr, sz);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::device& device, void* userptr, size_t sz, xrt::ext::bo::access_mode access)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::device&, void*, size_t, xrt::ext::bo::access_mode)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::device&, void*, size_t, xrt::ext::bo::access_mode);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, userptr, sz, access);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::device& device, xrt::pid_type pid, xrt::bo::export_handle ehdl)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::device&, xrt::pid_type, xrt::bo::export_handle)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::device&, xrt::pid_type, xrt::bo::export_handle);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, pid, ehdl);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::hw_context& hwctx, size_t sz)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::hw_context&, size_t)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::hw_context&, size_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, hwctx, sz);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::hw_context& hwctx, size_t sz, xrt::ext::bo::access_mode access)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::hw_context&, size_t, xrt::ext::bo::access_mode)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::hw_context&, size_t, xrt::ext::bo::access_mode);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, hwctx, sz, access);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ext::bo::
bo(const xrt::hw_context& hwctx, xrt::pid_type pid, xrt::bo::export_handle ehdl)
{
  const char* func_s = "xrt::ext::bo::bo(const xrt::hw_context&, xrt::pid_type, xrt::bo::export_handle)";
  typedef xrt::ext::bo* (*func_t)(void*, const xrt::hw_context&, xrt::pid_type, xrt::bo::export_handle);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, hwctx, pid, ehdl);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
