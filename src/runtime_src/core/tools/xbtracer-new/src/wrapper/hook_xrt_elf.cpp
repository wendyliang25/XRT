#include <wrapper/hook_xrt.h>

xrt::elf::
elf(const std::string& fnm)
{
  const char* func_s = "xrt::elf::elf(const std::string&)";
  typedef xrt::elf* (*func_t)(void*, const std::string&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, fnm);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::elf::
elf(const void * data, size_t size)
{
  const char* func_s = "xrt::elf::elf(const void *, size_t)";
  typedef xrt::elf* (*func_t)(void*, const void *, size_t);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, data, size);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::elf::
elf(std::istream& stream)
{
  const char* func_s = "xrt::elf::elf(std::istream&)";
  typedef xrt::elf* (*func_t)(void*, std::istream&);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, stream);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::uuid
xrt::elf::
get_cfg_uuid() const
{
  const char* func_s = "xrt::elf::get_cfg_uuid(void)";
  typedef xrt::uuid (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_member_func_entry_handle(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  xrt::uuid ret_o = ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_member_func_exit_handle(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);

  return ret_o;
}
