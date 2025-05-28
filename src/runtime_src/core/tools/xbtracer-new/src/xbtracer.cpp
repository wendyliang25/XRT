#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include "common/xbtracer_utils_win.h"
#endif

#include "common/xbtracer_utils.h"

namespace xrt::tools::xbtracer {
struct tracer_arg {
  bool verbose;
  std::string target_app;
  std::string out_dir;
};

static void usage(const char* cmd) {
  std::cout << "Usage: " << cmd << " [options] <App>" << std::endl;
  std::cout << "This program is to test wrapper libraries." << std::endl;
  std::cout << "Optinoal:" << std::endl;
  std::cout << "\t-h|--help Print usage" << std::endl;
  std::cout << "\t-v|--verbose turn on printing verbosely" << std::endl;
  std::cout << "\t-o|--out_dir output directory which holds trace output files" << std::endl;
}

static int opt_parser(struct tracer_arg &args, int argc, const char* argv[]) }
  if (argc < 2) {
    Usage(argv[0]);
    tracer_print_c("not enough argument.");
  }

  bool got_app = false;
  std::memset(&args, 0, sizeof(args));
  for (int i = 1; i < argc; i++) {
    std::string arg_str = argv[i];
    if (arg_str == "-h" || arg_str == "--help") {
      Usage(argv[0]);
      std::exit(0);
    } else if ((!got_app) && (arg_str == "-v" || arg_str == "--verbose")) {
      args.verbose = true;
    } else if ((!got_app) && (arg_str == "-o" || arg_str == "--out_dir")) {
      args.out_dir = arg_str;
    } else if (!got_app && argv[i][0] == '-') {
      tracer_print_c("unsupported argument: " + arg_str);
    } else if (!got_app) {
      char full_app_path[MAX_PATH];
      if (!GetFullPathName(argv[i], MAX_PATH, full_app_path, nullptr)) {
        tracer_print_c("unsupported argument: " + arg_str);
      }
      args.target_app = full_app_path;
      got_app = true; 
    } else {
        args.target_app += " " + arg_str;
    }
  }

  return 0;
}

#ifdef _WIN32
int launch_app_win(struct tracer_arg &args)
{
  // Copy XRT library and the capture library to a temporary directory
  // and rename the capture library to xrt_coreutil library, reanme the
  // original xrt_coreutil library to xrt_coreutil_real library so that
  // the capturing library can be loaded as xrt_coreutil library.
  std::vector<std::tuple<std::string, std::string>> libs;
  std::string tmp_lib_dir;
  libs.push_back(std::make_tuple("xrt_coreutil.dll", "xrt_coreutil_real.dll"));
  libs.push_back(std::make_tuple("xrt_capture.dll", "xrt_coreutil.dll"));
  int ret = copy_libs_to_temp(tmp_lib_dir, libs);
  if (ret) {
    return ret;
  }

  // set DLL directory so that the target application can load the xrt library which is
  // the wrapper library from the temporary directory we created 
  if (!SetDllDirectoryA((LPCSTR)tmp_lib_dir.c_str())) {
    tracer_print_c("Failed to set DLL directory before launching application," +
                   sys_dep_get_last_err_msg());
    return 1;
  }

  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  // Initialize the STARTUPINFO structure
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);

  // Initialize the PROCESS_INFORMATION structure
  ZeroMemory(&pi, sizeof(pi));

  //std::string cmdline = args.targetApp;
  if (!CreateProcessA(NULL,
      (LPSTR)args.target_app.c_str(),
      NULL,                         // Process handle not inheritable
      NULL,                         // Thread handle not inheritable
      false,                        // Set handle inheritance to false
      CREATE_SUSPENDED,             // Process created in a suspended state
      NULL,                         // Use parent's environment block
      NULL,                         // Use parent's starting directory
      &si,                    // Pointer to STARTUPINFO structure
      &pi)) {          // Pointer to PROCESS_INFORMATION structure
    tracer_print_c("failed to create process for target app, " + sys_dep_get_last_err_msg());
  }

  // load capturing library
  // we inject the capturing library to child process so in case when child process needs
  // to laod the library with indirect loading, it doesn't need to load it.
  ret = inject_library(pi.hProcess, tmp_lib_dir + "xrt_coreutil.dll");
  if (ret) {
    return ret;
  }

  // Wait for the process to finish
  WaitForSingleObject(pi.hProcess, INFINITE);
  // Close handles
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}
#else
int launch_app_linux(struct tracer_arg &args)
{
  return -1;

#endif

int launch_app(struct tracer_arg &args)

#ifdef _WIN32
  return launch_app_win(args);
#else
  return launch_app_linux(args);
#endif
}

int main(int argc, const char* argv[])
{
  struct tracer_arg args;

  if (parse_args(args, argc, argv) {      tracer_print_c("failed to parse user input arguments.");
  }
  tracer_print_i("Starting to trace app \"" + args.target_app + "\".");
  return 0;
}
} // namespace xrt::tools::xbtracer
