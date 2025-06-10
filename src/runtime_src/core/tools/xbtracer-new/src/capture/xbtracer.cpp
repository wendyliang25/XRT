// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <capture/xbtracer.h>
#include <common/trace_utils.h>

using namespace xrt::tools::xbtracer;

static void usage(const char* cmd) {
  std::cout << "Usage: " << cmd << " [options] <App>" << std::endl;
  std::cout << "This program is to test wrapper libraries." << std::endl;
  std::cout << "Optinoal:" << std::endl;
  std::cout << "\t-h|--help Print usage" << std::endl;
  std::cout << "\t-v|--verbose turn on printing verbosely" << std::endl;
  std::cout << "\t-o|--out_dir output directory which holds trace output files" << std::endl;
}

static int parse_args(struct tracer_arg &args, int argc, const char* argv[])
{
  if (argc < 2) {
    usage(argv[0]);
    std::cerr << "ERROR: xbtracer: not enough argument." << std::endl;
  }

  args.verbose = false;
  bool got_app = false;
  for (int i = 1; i < argc; i++)
  {
    std::string arg_str = argv[i];
    if (arg_str == "-h" || arg_str == "--help")
    {
      usage(argv[0]);
      std::exit(0);
    }
    else if ((!got_app) && (arg_str == "-v" || arg_str == "--verbose"))
    {
      args.verbose = true;
    }
    else if ((!got_app) && (arg_str == "-o" || arg_str == "--out_dir"))
    {
      args.out_dir = arg_str;
    }
    else if (!got_app && argv[i][0] == '-')
    {
      std::cerr << "ERROR: xbtracer: unsuppocrted argument: " + arg_str << std::endl;
    }
    else if (!got_app)
    {
      std::filesystem::path given_path = argv[i];
      std::filesystem::path full_app_path = std::filesystem::absolute(given_path);
      args.target_app.push_back(full_app_path.string());
      got_app = true;
    }
    else
    {
      args.target_app.push_back(arg_str);
    }
  }

  return 0;
}

static int init_logger(const struct tracer_arg &args)
{
  int ret;
  // setup logger environment variable, as we need to pass them to child process
  ret = setenv_os("XBRACER_PRINT_NAME", "xbtracer");
  const char* plevel_str = "INFO";
  if (args.verbose)
  {
    plevel_str = "DEBUG";
  }
  ret |= setenv_os("XBRACER_PRINT_LEVEL", plevel_str);

  if (ret)
  {
    std::cerr << "ERROR: xbracer: failer to set logging env." << std::endl;
    return -EINVAL;
  }
  return 0;
}

static int init_tracer(const struct tracer_arg &args)
{
  std::filesystem::path opath;
  if (args.out_dir.empty())
  {
    opath = std::filesystem::current_path();
  }
  else
  {
    opath = args.out_dir;
  }
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm local_time;
  localtime_os(local_time, t);
  std::ostringstream oss;
  oss <<  std::put_time(&local_time, "%Y%m%d_%H%M%S");
  opath.append("trace_" + oss.str());
  std::string opath_str = opath.string();

  std::error_code ec;
  bool created = std::filesystem::create_directories(opath, ec);
  if (!created)
  {
    xbtracer_pcritical("failed to create tracer directory \"", opath_str, "\", ", ec.message(), "\".");
  }

  int ret = setenv_os("XBTRACER_OUT_DIR", opath_str.c_str());
  if (ret)
  {
    xbtracer_pcritical("failed to set tracer output file \"", opath.string(), "\".");
  }
  xbtracer_pinfo("tracer output to directory \"", opath.string(), "\".");
  return 0;
}

int main(int argc, const char* argv[])
{
  struct tracer_arg args;

  if (parse_args(args, argc, argv))
  {
    std::cerr << "ERRPR: xbtracer: failed to parse user input arguments." << std::endl;
  }

  init_logger(args);
  init_tracer(args);
  xbtracer_pinfo("Starting to trace app \"", args.target_app[0], "\".");
  return launch_app(args);
}
