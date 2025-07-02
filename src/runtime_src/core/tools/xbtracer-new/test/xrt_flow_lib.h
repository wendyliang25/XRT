#ifndef xrt_flow_lib_h
#define xrt_flow_lib_h

#include <cstring>

#ifdef _WIN32
#define TEST_API_EXPORT __declspec(dllexport)
#else
#define TEST_API_EXPORT
#endif
extern "C" {
TEST_API_EXPORT
int xrt_call_test(const char* xclbin_name);

TEST_API_EXPORT
int xrt_call_crash_test(const char* xclbin_name);
};
#endif // xrt_flow_lib_h
