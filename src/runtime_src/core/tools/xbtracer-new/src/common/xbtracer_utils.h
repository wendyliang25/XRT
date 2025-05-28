// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef xbtracer_utils_h
#define xbtracer_utils_h
#include <iostream>
#include <string>
#include <vector>
#include <tuple>

namespace xrt::tools::xbtracer {
/*
 * This function template appends a given value of any type to the specified
 * output string stream and recursively processes additional values if provided.
 * It terminates when there are no more values to process.
 */
template <typename... Args>
void print_format(std::ostringstream& oss, const Args&... args)
{
  (oss << ... << args); //NOLINT
}

enum class log_level {
  DEBUG = 0,
  INFO,
  ERROR,
  CRITICAL,
};
/*
 * Function to trace the error log
 */
template <typename... Args>
void print_prefix_format(log_level level, const std::string &prefix, const Args&... args)
{
  std::ostringstream oss;
  std::string level_str;
  if (level == log_level::DEBUG) {
    level_str = "DEBUG";
  } else if (level == log_level::INFO) {
    level_str = "INFO";
  } else if (level == log_level::ERROR) {
    level_str = "ERROR";
  } else if (level == log_level::CRITICAL) {
    level_str = "CRITICAL";
  }
  oss << level_str << ": [" << prefix << "]: ";
  log_format(oss, args...);
  std::cout << oss.str() << std::endl;
}

/*
 * Function to trace the fatal log
 */
template <typename... Args>
void print_c(const std::string &prefix, const Args&... args)
{
  print_prefix_format("CRITICAL", prefix, args...);
  throw std::runtime_error(oss.str() + ". Aborted!\n");
}

/*
 * Function to trace the error log
 */
template <typename... Args>
void print_e(const std::string &prefix, const Args&... args)
{
  print_prefix_format("ERROR", prefix, args...);
}

/*
 * Function to trace the debug log
 */
template <typename... Args>
void print_i(const std::string &prefix, const Args&... args)
{
  print_prefix_format("INFO", prefix, args...);
}

/*
 * Function to trace the debug log
 */
template <typename... Args>
void print_d(const std::string &prefix, const Args&... args)
{
  if (launcher::get_instance().m_debug)
  {
    print_prefix_format("DEBUG", prefix, args...);
  }
}

template <typename... Args>
void tracer_print_c(const Args&... args)
{
    print_c("tracer", args...);
}

template <typename... Args>
void tracer_print_e(const Args&... args)
{
    print_e("tracer", args...);
}

template <typename... Args>
void tracer_print_i(const Args&... args)
{
    print_i("tracer", args...);
}

template <typename... Args>
void tracer_print_d(const Args&... args)
{
    print_d("tracer", args...);
}

} // namespace xrt::tools::xbtracer
#endif // xbtracer_utils_h
