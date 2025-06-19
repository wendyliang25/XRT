#include <wrapper/hook_xrt.h>

std::cv_status
xrt::ip::interrupt::
wait(const std::chrono::milliseconds& timeout) const
{
  const char* func_s = "xrt::ip::interrupt::wait(const std::chrono::milliseconds&)";
  typedef std::cv_status (*func_t)(void*, const std::chrono::milliseconds&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  std::cv_status ret_o = ofunc((void*)this, timeout);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}

uint32_t
xrt::ip::
read_register(uint32_t offset) const
{
  const char* func_s = "xrt::ip::read_register(uint32_t)";
  typedef uint32_t (*func_t)(void*, uint32_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  uint32_t ret_o = ofunc((void*)this, offset);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}

void
xrt::ip::interrupt::
disable()
{
  const char* func_s = "xrt::ip::interrupt::disable(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::ip::interrupt::
enable()
{
  const char* func_s = "xrt::ip::interrupt::enable(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::ip::interrupt::
wait()
{
  const char* func_s = "xrt::ip::interrupt::wait(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::ip::
write_register(uint32_t offset, uint32_t data)
{
  const char* func_s = "xrt::ip::write_register(uint32_t, uint32_t)";
  typedef void (*func_t)(void*, uint32_t, uint32_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, offset, data);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ip::interrupt
xrt::ip::
create_interrupt_notify()
{
  const char* func_s = "xrt::ip::create_interrupt_notify(void)";
  typedef xrt::ip::interrupt (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  xrt::ip::interrupt ret_o = ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}

xrt::ip::
ip(const xrt::device& device, const xrt::uuid& xclbin_id, const std::string& name)
{
  const char* func_s = "xrt::ip::ip(const xrt::device&, const xrt::uuid&, const std::string&)";
  typedef xrt::ip* (*func_t)(void*, const xrt::device&, const xrt::uuid&, const std::string&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, device, xclbin_id, name);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::ip::
ip(const xrt::hw_context& ctx, const std::string& name)
{
  const char* func_s = "xrt::ip::ip(const xrt::hw_context&, const std::string&)";
  typedef xrt::ip* (*func_t)(void*, const xrt::hw_context&, const std::string&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, ctx, name);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
