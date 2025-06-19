#include <wrapper/hook_xrt.h>

void
xrt::profile::user_event::
mark(const char* label)
{
  const char* func_s = "xrt::profile::user_event::mark(const char*)";
  typedef void (*func_t)(void*, const char*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, label);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::profile::user_event::
mark_time_ns(const std::chrono::nanoseconds& time_ns, const char* label)
{
  const char* func_s = "xrt::profile::user_event::mark_time_ns(const std::chrono::nanoseconds&, const char*)";
  typedef void (*func_t)(void*, const std::chrono::nanoseconds&, const char*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, time_ns, label);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::profile::user_range::
end()
{
  const char* func_s = "xrt::profile::user_range::end(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

void
xrt::profile::user_range::
start(const char* label, const char* tooltip)
{
  const char* func_s = "xrt::profile::user_range::start(const char*, const char*)";
  typedef void (*func_t)(void*, const char*, const char*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, label, tooltip);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::profile::user_event::
user_event()
{
  const char* func_s = "xrt::profile::user_event::user_event(void)";
  typedef xrt::profile::user_event* (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::profile::user_event::
~user_event()
{
  const char* func_s = "xrt::profile::user_event::~user_event(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_destructor_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::profile::user_range::
user_range()
{
  const char* func_s = "xrt::profile::user_range::user_range(void)";
  typedef xrt::profile::user_range* (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::profile::user_range::
user_range(const char* label, const char* tooltip)
{
  const char* func_s = "xrt::profile::user_range::user_range(const char*, const char*)";
  typedef xrt::profile::user_range* (*func_t)(void*, const char*, const char*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this, label, tooltip);

  xbtracer_proto::Func func_exit;
  xbtracer_init_func_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}

xrt::profile::user_range::
~user_range()
{
  const char* func_s = "xrt::profile::user_range::~user_range(void)";
  typedef void (*func_t)(void*);
  xbtracer_proto::Func func_entry;
  proc_addr_type paddr_ptr;
  bool need_trace;

  xbtracer_init_func_entry(func_entry, need_trace, func_s, paddr_ptr);
  xbtracer_write_protobuf_msg(func_entry, need_trace);
  func_t ofunc = (func_t)paddr_ptr;

  ofunc((void*)this);

  xbtracer_proto::Func func_exit;
  xbtracer_init_destructor_exit(func_exit, need_trace, func_s);
  xbtracer_write_protobuf_msg(func_exit, need_trace);
}
