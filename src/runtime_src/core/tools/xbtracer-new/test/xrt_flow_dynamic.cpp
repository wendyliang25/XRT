#include <cerrno> 
#include <cstring>
#include <iostream>
#include "xrt_flow_lib.h"

typedef int (*test_func_type)(const char*); // Define function pointer type

#ifdef _WIN32
#include <windows.h>
inline std::string
sys_dep_get_last_err_msg()
{
  DWORD error_code = GetLastError();
  LPVOID error_msg;
  FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    error_code,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPTSTR)&error_msg,
    0,
    NULL);
  std::string error_message = static_cast<char*>(error_msg);
  LocalFree(error_msg);
  return error_message;
}

static void test_xrt_flow(const char* xclbin_name)
{
  HMODULE hDll = LoadLibrary(TEXT("test_xrt_lib.dll"));
  if (!hDll) {
    std::cout << "ERROR: failed to open test xrt library, " << sys_dep_get_last_err_msg() << "." << std::endl;
    return;
  }

  test_func_type mfunc = (test_func_type)GetProcAddress(hDll, "xrt_call_test");
  if (!mfunc) {
    std::cout << "ERROR: failed to load test function symbol, " << sys_dep_get_last_err_msg() << "." << std::endl;
    return;
  }
  (void)mfunc(xclbin_name);
}
#else
#include <dlfcn.h>

static void test_xrt_flow(const char* xclbin_name)
{
  void* handle = dlopen("libtest_xrt_lib.so", RTLD_LAZY); // RTLD_LAZY means symbols are resolved as needed
  if (!handle) {
    std::cout << "ERROR: failed to open test xrt library, " << strerror(errno) << "." << std::endl;
    return;
  }
  test_func_type mfunc = (test_func_type)dlsym(handle, "xrt_call_test");
  if (!mfunc) {
    std::cout << "ERROR: failed to load test function symbol, " << strerror(errno) << "." << std::endl;
    return;
  }
  (void)mfunc(xclbin_name);
}
#endif

int main(int argc, const char* argv[])
{
  if (argc < 2) {
   std::cout << "ERROR: please pass xclbin file name." << std::endl;
   return -1;
  }
  std::cout << "Testing calling XRT API with xclbin: " << std::string(argv[1]) << "." << std::endl;
  (void)test_xrt_flow(argv[1]);
  std::cout << "Test done. " << std::endl;

  return 0;
}
