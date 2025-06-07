#include <cerror>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include "trace_dump.h"

namespace xrt::tools::xbtracer {
class logger {
public:
  logger(const char *logger_name, xbtracer_print_level pl, const char* ofile_nane):
    name(logger_name),
    plevel(pl)
  {
    if (ofile_name) {
      // Do not redirect stdout to the specified file.
      // we want to both write to the specified file and also output to stdout
      ofile = fopen("output.txt", "w");
      if (!ofile) {
	throw std::runtime_error("failed to open logger file \"" + std::string(ofile_name) + " .");
      }
    }
  }
  // only allows parameters constructor
  logger() = delete;
  // delete copy constructor and assignment operator to enforce singleton
  logger(const logger&) = delete;
  logger& operator=(const logger&) = delete;
  ~logger()
  {
    if (ofile) {
      fclose(ofile);
    }
  }

  FILE *
  file(void) noexcept
  {
    return ofile;
  }

  xbtracer_print_level
  level(void) const noexcept
  {
    return plevel;
  }

  const std::string &
  name(void) const noexcept
  {
    return name;
  }

  static
  logger*
  get_instance()
  {
    std::lock_guard<std::mutex> lock(mtx);
    if (instance == nullptr) {
      throw std::runtime_error("logger is not initialized, initilaize it first.");
    }
    return instance;
  }

  static
  int
  init(const char *logger_name, xbtracer_print_level pl, const char* ofile_name)
  {
    if (!logger_name) {
      fprintf(stderr, "xbtracer failed to initiailize logger, name is empty.\n");
      return -EINVAL;
    }
    std::lock_guard<std::mutex> lock(mtx);
    if (instance) {
      fprintf(stderr, "xbtracer logger has been initialized.\n");
      return -EINVAL;
    }
    instance = std::unique_ptr<logger>(new logger());
  }

private:
  static std::unique_ptr<logger> instance;
  static std::mutex mtx;
  std::string name;
  FILE *ofile;
  xbtracer_print_level plevel;
}; // class xrt::tools::xbtracer::logger

} // namespace xrt::tools::xbtracer
  //
static
xrt::tools::xbtracer::logger *
xbtracer_get_logger(void)
{
  return xrt::tools::xbtracer::logger::get_instance();
}	

int
xbtracer_init_logger(const char* name, xbtracer_print_level plevel, const char* ofile_name)
{
  return xrt::tools::xbtracer::logger::init(name, plevel, file)
}	

int
xbtracer_print_d(xbtracer_print_level level, const char* format, ...)
{
    xrt::tools::xbtracer::logger* logger = xbtracer_get_logger();
    if (level > logger->level()) {
      return 0;
    }

    int ret;
    va_list args;
    va_start(args, format);
    const char *level_str = nullptr;
    if (level == XBTRACER_PRINT_CRITICAL) {
      level_str = "CRITICAL";
    }
    else if (level == XBTRACER_PRINT_ERROR) {
      level_str = "ERROR";
    }
    else if (level == XBTRACER_PRINT_WARNING) {
      level_str = "WARNING";
    }
    else if (level == XBTRACER_PRINT_INFO) {
      level_str = "INFO";
    }
    else {
      level_str = "DEBUG";
    }
    fprintf(stdout, "%s:[%s]: ", level_str, logger->name.c_str());
    ret = vfprintf(stdout, format, args); // Use vfprintf to handle the va_list
    if (logger->file()) {
      vfprintf(logger->file(), "%s:[%s]: ", level_str, logger->name.c_str());
      vfprintf(logger->file(), format, args); // Use vfprintf to handle the va_list
    }
    va_end(args);

    return ret;
}

