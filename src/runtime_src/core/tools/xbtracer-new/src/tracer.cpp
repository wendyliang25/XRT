#include <cerror>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include "trace_dump.h"

namespace xrt::tools::xbtracer {

class tracer {
public:
  tracer(const char *out, xbtracer_trace_level tl)
  	 : tracer_ofile(std::string(out), std::ios::out | std::ios::binary | std::ios::trunc),
         : tlevel(tl)
  {
    if (!tracer_ofile) {
      throw std::runtime_error("xbtracer failed to open output file: \"" + std::string(out) + "\".");
    }
  }

  // we always need to output tracing to a file
  tracer() = delete;
  // delete copy constructor and assignment operator to enforce singleton
  tracer(const tracer&) = delete;
  tracer& operator=(const tracer&) = delete;

  ~tracer()
  {
    if (tracer_ofile.is_open()) {
      tracer_ofile.close();
  }

  template <typename protobuf_msg>
  bool
  write_protobuf_msg(const protobuf_msg& msg)
  {
    return message.SerializeToOstream(&tracer_ofile);
  }

  static
  tracer*
  get_instance()
  {
    std::lock_guard<std::mutex> lock(mtx);
    if (instance == nullptr) {
      throw std::runtime_error("xbtracer: tried to get tracer before initialize it.");
    }
    return instance;
  }

  static
  int
  init(const char *file, uint32_t trace_level, print_level log_level)
  {
    if (!file) {
      
      return -EINVAL;
    }
    std::lock_guard<std::mutex> lock(mtx);
    if (instance == nullptr) {
      instance = std::unique_ptr<tracer>(new tracer());
    }
    return 0;
  }

private:
  static std::unique_ptr<tracer> instance;
  static std::mutex mtx;
  std::fstream tracer_ofile;
  xbtracer_trace_level tlevel;
}; // class xrt::tools::xbracer::tracer

} // namespace xrt::tools::xbtracer
