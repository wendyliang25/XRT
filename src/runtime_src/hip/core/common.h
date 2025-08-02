// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
#ifndef xrthip_common_h
#define xrthip_common_h

#include "core/common/error.h"

#include "hip/config.h"
#include "hip/hip_runtime_api.h"

#include "context.h"
#include "device.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <stack>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xrt::core::hip {
struct ctx_info
{
  context_handle ctx_hdl{nullptr};
  bool active{false};
};

// thread local hip objects
struct hip_tls_objs
{
  hip_tls_objs() noexcept {}
  device_handle dev_hdl{std::numeric_limits<uint32_t>::max()};
  std::stack<std::weak_ptr<context>> ctx_stack;
  ctx_info pri_ctx_info;
};
extern thread_local hip_tls_objs tls_objs;

// generic function for adding shared_ptr to handle_map
// {key , value} -> {shared_ptr.get(), shared_ptr}
// returns void* (handle returned to application)
template<typename map, typename value>
inline void*
insert_in_map(map& m, value&& v)
{
  auto handle = v.get();
  m.add(handle, std::move(v));
  return handle;
}

template <typename K, typename T>
class hip_container {
private:
  uint32_t m_max{0};
  std::unordered_map<const K*, std::vector<T>> m_map;
  std::mutex m_mutex; // lock to the map
  uint32_t m_size{0};
  std::condition_variable m_cv;
  uint32_t m_nocache{0}; // flag to indicate if caching is stopped
public:
  hip_container(uint32_t max): m_max(max) {};
  hip_container(const hip_container&) = delete;
  hip_container& operator=(const hip_container&) = delete;
  hip_container&& operator=(const hip_container&&) = delete;
  ~hip_container() = default;

  void
  push(const K* k, T&& t)
  {
    std::scoped_lock<std::mutex> lock(m_mutex);

    if (m_size >= m_max || m_nocache != 0)
      return;

    auto it = m_map.find(k);
    if (it == m_map.end()) {
      std::vector<T> temp_vec;
      temp_vec.push_back(std::move(t));
      m_map.emplace(k, std::move(temp_vec));
    }
    else {
      auto& temp_vec = it->second;
      temp_vec.push_back(std::move(t));
    }
    m_size++;
  }

  std::optional<T>
  get(const K* k)
  {
    std::scoped_lock<std::mutex> lock(m_mutex);
    auto it = m_map.find(k);
    if (it != m_map.end()) {
      if (!it->second.empty()) {
	T t = std::move(it->second.back());
	it->second.pop_back();
	m_size--;
	return t;
      }
    }
    return std::nullopt;
  }

  void
  remove(const K* k)
  {
    std::scoped_lock<std::mutex> lock(m_mutex);
    auto it = m_map.find(k);
    if (it != m_map.end()) {
      if (it->second.size()) {
        m_size -= it->second.size();
        it->second.clear();
      }
      m_map.erase(it);
    }
  }

  void
  stop_caching()
  {
    std::scoped_lock<std::mutex> lock(m_mutex);
    if (!m_nocache && m_size) {
      m_map.clear();
      m_size = 0;
    }
    m_nocache++;
  }

  void
  resume_caching()

  {
    std::scoped_lock<std::mutex> lock(m_mutex);
    if (m_nocache <= 0) {
      throw xrt_core::system_error(hipErrorInvalidValue,
				   "hip_container caching is not stopped");
    }
    m_nocache--;
  }

  static
  std::shared_ptr<hip_container<K, T>>
  get_instance(uint32_t max)
  {
    static std::shared_ptr<hip_container<K, T>> instance(new hip_container<K, T>(max));
    if (max != instance->m_max) {
      throw xrt_core::system_error(hipErrorInvalidValue,
                                   "hip_container max size cannot be changed after creation");
    }
    return instance;
  }
};
} // xrt::core::hip

namespace {
// common functions for throwing hip errors
inline void
throw_if(bool check, hipError_t err, const char* err_msg)
{
  if (check)
    throw xrt_core::system_error(err, err_msg);
}

inline void
throw_invalid_value_if(bool check, const char* err_msg)
{
  throw_if(check, hipErrorInvalidValue, err_msg);
}

inline void
throw_invalid_handle_if(bool check, const char* err_msg)
{
  throw_if(check, hipErrorInvalidHandle, err_msg);
}

inline void
throw_invalid_device_if(bool check, const char* err_msg)
{
  throw_if(check, hipErrorInvalidDevice, err_msg);
}

inline void
throw_invalid_resource_if(bool check, const char* err_msg)
{
  throw_if(check, hipErrorInvalidResourceHandle, err_msg);
}

inline void
throw_context_destroyed_if(bool check, const char* err_msg)
{
  throw_if(check, hipErrorContextIsDestroyed, err_msg);
}
}
#endif

