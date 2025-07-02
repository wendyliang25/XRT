#include <iostream>
#include "xrt_flow_lib.h"

int main(int argc, const char* argv[])
{
  if (argc < 2) {
   std::cout << "ERROR: please pass xclbin file name." << std::endl;
   return -1;
  }
  std::cout << "Testing calling XRT API with xclbin: " << std::string(argv[1]) << "." << std::endl;
  (void)xrt_call_test(argv[1]);
  std::cout << "Test done. " << std::endl;

  return 0;
}
