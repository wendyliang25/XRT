#ifndef trace_utils_h
#define trace_utils_h

#include <iostream>
#include <typeinfo>

namespace xrt::tools::xbtracer {


} // namespace xrt::tools::xbtracer

// XRT tracer/replay print message debugging level
enum xbtracer_print_level {
  XBTRACER_PRINT_CRITICAL = 0,
  XBTRACER_PRINT_ERROR = 1,
  XBTRACER_PRINT_WARNING = 2,
  XBTRACER_PRINT_INFO = 3,
  XBTRACER_PRINT_VERBOSE = 4,
};

// TODO: only support single tracing level
enum xbtracer_trace_level {
  XBTRACER_TRACE_DEFAULT = 0,
};

extern "C" {
int
xbtracer_print_d(xbtracer_print_level level, const char* format, ...);
};

#define xbtracer_pcritical(format, ...) \
  xrt::tools::xbtracer::print_d(XBTRACER_PRINT_CRITICAL, format, ##__VA_ARGS__)
#define xbtracer_perror(format, ...) \
  xbtracer_print_d(XBTRACER_PRINT_ERROR, format, ##__VA_ARGS__)
#define xbtracer_pwarn(format, ...) \
  xbtracer_print_d(XBTRACER_PRINT_WARNING, format, ##__VA_ARGS__)
#define xbtracer_pinfo(format, ...) \
  xbtracer_print_d(XBTRACER_PRINT_INFO, format, ##__VA_ARGS__)
#define xbtracer_pdebug(format, ...) \
  xbtracer_print_d(XBTRACER_PRINT_DEBUG, format, ##__VA_ARGS__)

int
xbtracer_init_logger(const char* name, xbtracer_print_level plevel, const char* ofile_name);

int xbtracer_log_func_sig(const std::string &func_sig);

template <typename Arg, typename... Args>
void xbtracer_log_func_args(int func_id, const Arg& arg, const Args&... args) {
	std::cout << 
}

#endif // trace_utils_h
