// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025 Advanced Micro Devices, Inc. All rights reserved.
#ifndef xrthip_module_h
#define xrthip_module_h

#include "common.h"
#include "context.h"
#include "core/include/xrt/experimental/xrt_ext.h"
#include "core/include/xrt/xrt_hw_context.h"
#include "core/include/xrt/xrt_kernel.h"

#include <mutex>
#include <vector>
#include <thread>

namespace xrt::core::hip {

// module_handle - opaque module handle
using module_handle = void*;

// function_handle - opaque function handle
using function_handle = void*;

// forward declaration
class function;

// hipModuleLoad load call of hip is used to load xclbin
// hipModuleLoadData call is used to load elf
// In both cases hipModule_t is returned which holds pointer to
// objects of module_xclbin/module_elf dervied from base class module
class module
{
protected:
  std::shared_ptr<context> m_ctx;
  bool m_is_xclbin;

public:
  module(std::shared_ptr<context> ctx, bool is_xclbin)
    : m_ctx{std::move(ctx)}
    , m_is_xclbin{is_xclbin}
  {}

  bool
  is_xclbin_module() const
  {
    return m_is_xclbin;
  }

  std::shared_ptr<context>
  get_context() const
  {
    return m_ctx;
  }

  virtual
  ~module() = default;
};

class module_xclbin : public module
{
  xrt::xclbin m_xrt_xclbin;
  xrt::hw_context m_xrt_hw_ctx;
  xrt_core::handle_map<function_handle, std::shared_ptr<function>> function_cache;

public:
  module_xclbin(std::shared_ptr<context> ctx, const std::string& file_name);

  module_xclbin(std::shared_ptr<context> ctx, void* data, size_t size);

  function_handle
  add_function(std::shared_ptr<function> f)
  {
    return insert_in_map(function_cache, f);
  }

  std::shared_ptr<function>
  get_function(function_handle handle) const
  {
    return function_cache.get(handle);
  }

  const xrt::hw_context&
  get_hw_context() const
  {
    return m_xrt_hw_ctx;
  }
};

class module_elf : public module
{
  module_xclbin* m_xclbin_module;
  xrt::elf m_xrt_elf;
  xrt::module m_xrt_module;

public:
  module_elf(module_xclbin* xclbin_module, const std::string& file_name);

  module_elf(module_xclbin* xclbin_module, void* data, size_t size);

  module_xclbin*
  get_xclbin_module() const { return m_xclbin_module; }

  const xrt::module&
  get_xrt_module() const { return m_xrt_module; }
};

class function
{
  module_xclbin* m_xclbin_module = nullptr;
  std::string m_func_name;
  xrt::kernel m_xrt_kernel;
  std::shared_ptr<hip_container<function, xrt::run>> m_runs_container;

public:
  function() = default;
  function(module_xclbin* mod_hdl, const xrt::module& xrt_module, const std::string& name);
  ~function()
  {
    if (m_runs_container) {
      m_runs_container->remove(this);
    }
  }

  module_xclbin*
  get_module() const
  {
    return m_xclbin_module;
  }

  const xrt::kernel&
  get_kernel() const
  {
    return m_xrt_kernel;
  }

  xrt::run
  get_run()
  {
    auto opt_run = m_runs_container->get(this);
    if (opt_run)
      return opt_run.value();

    try {
      auto run = xrt::run(m_xrt_kernel);
      return run;
    }
    catch (const xrt_core::system_error& e) {
      if (e.get() == ENOSPC) {
        m_runs_container->stop_caching();
        auto run = xrt::run(m_xrt_kernel);
        m_runs_container->resume_caching();
        return run;
      } else {
        throw; // rethrow other exceptions which are not ENOSPC
      }
    }
    catch (...) {
      throw; //Catch all other exceptions and rethrow
    }
  }

  void
  release_run(xrt::run&& run)
  {
    m_runs_container->push(this, std::move(run));
  }
};

extern xrt_core::handle_map<module_handle, std::shared_ptr<module>> module_cache;
} // xrt::core::hip

#endif
