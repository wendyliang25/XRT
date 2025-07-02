#include <cstring>
#include <stdexcept>
#include <iostream>
#include <string>

// XRT includes
#include "xrt.h"
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "xrt/experimental/xrt_elf.h"
#include "xrt/experimental/xrt_module.h"
#include "xrt/experimental/xrt_ext.h"

#include "xrt_flow_lib.h"

int xrt_call_test(const char* xclbin_name)
{
  std::cout << "Simple XRT calls test..." << std::endl;
  unsigned int device_index = 0;
  auto device = xrt::device(device_index);
  auto xclbin = xrt::xclbin(std::string(xclbin_name));
  // Determine The DPU Kernel Name
  auto xkernels = xclbin.get_kernels();
  auto iteratorFound = std::find_if(xkernels.begin(), xkernels.end(), [](xrt::xclbin::kernel& k) {
    auto name = k.get_name();
    bool found = ((name.rfind("DPU",0) == 0) || // Starts with "DPU"
                  (name.rfind("dpu",0) == 0));   // Starts with "dpu"
    return found;
  });

  if (iteratorFound == xkernels.end()){
    std::cout << "Error: xclbin does not have a valid kernel" << std::endl;
    return -1;
  }

  xrt::xclbin::kernel& xkernel = *iteratorFound;
  auto kernelName = xkernel.get_name();
  std::cout << "Device resgiter xclbin." << std::endl;
  device.register_xclbin(xclbin);
  std::cout << "Creating context..." << std::endl;
  xrt::hw_context context(device, xclbin.get_uuid());
  std::cout << "Creating kernel object..." << std::endl;
  xrt::kernel kernel = xrt::kernel(context, kernelName);
  std::cout << "Creating bo..." << std::endl;
  auto bo_1 = xrt::bo(device, 1024, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(5));
  std::cout << "Created bo-1, size: " << bo_1.size() << std::endl;
  char* ptr_1 = reinterpret_cast<char*>(bo_1.map());
  if (!ptr_1) {
    std::cout << "ERROR: failed to map bo_1." << std::endl;
    return -1;
  }
  memset(ptr_1, 0, 1024);
  return 0;
}

int xrt_call_crash_test(const char* xclbin_name)
{
  std::cout << "Simple XRT calls test..." << std::endl;
  unsigned int device_index = 0;
  auto device = xrt::device(device_index);
  auto xclbin = xrt::xclbin(std::string(xclbin_name));
  // Determine The DPU Kernel Name
  auto xkernels = xclbin.get_kernels();
  auto iteratorFound = std::find_if(xkernels.begin(), xkernels.end(), [](xrt::xclbin::kernel& k) {
    auto name = k.get_name();
    bool found = ((name.rfind("DPU",0) == 0) || // Starts with "DPU"
                  (name.rfind("dpu",0) == 0));   // Starts with "dpu"
    return found;
  });

  if (iteratorFound == xkernels.end()){
    std::cout << "Error: xclbin does not have a valid kernel" << std::endl;
    return -1;
  }

  xrt::xclbin::kernel& xkernel = *iteratorFound;
  auto kernelName = xkernel.get_name();
  std::cout << "Device resgiter xclbin." << std::endl;
  device.register_xclbin(xclbin);
  std::cout << "Creating context..." << std::endl;
  xrt::hw_context context(device, xclbin.get_uuid());
  std::cout << "Creating kernel object..." << std::endl;
  xrt::kernel kernel = xrt::kernel(context, kernelName);
  std::cout << "Creating bo..." << std::endl;
  auto bo_1 = xrt::bo(device, 1024, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(5));
  std::cout << "Created bo-1, size: " << bo_1.size() << std::endl;
  char* ptr_1 = reinterpret_cast<char*>(bo_1.map());
  if (!ptr_1) {
    std::cout << "ERROR: failed to map bo_1." << std::endl;
    return -1;
  }
  memset(ptr_1, 0, 1024);
  {
    auto bo_2 = xrt::bo(device, 2048, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(5));
    bo_1 = bo_2;
  }
  std::cout << "bo - 1, size: " << bo_1.size() << std::endl;
  std::cout << "bo - 1, memset again..." << std::endl;
  memset(ptr_1, 0, 1024);
  std::cout << "bo - 1, memset again done. " << std::endl;
  return 0;
}
