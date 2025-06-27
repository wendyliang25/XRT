// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#ifndef xbreplay_common_h
#define xbreplay_common_h

#include <memory>
#include <mutex>
#include <queue>
#include <tuple>
#include <typeinfo>
#include <condition_variable>

#include <xrt.h>
#include <xrt/xrt_bo.h>
#include <xrt/xrt_aie.h>
#include <xrt/xrt_device.h>
#include <xrt/xrt_hw_context.h>
#include <xrt/xrt_kernel.h>
#include <xrt/xrt_uuid.h>
#include <xrt/experimental/xrt_ip.h>
#include <xrt/experimental/xrt_mailbox.h>
#include <xrt/experimental/xrt_module.h>
#include <xrt/experimental/xrt_kernel.h>
#include <xrt/experimental/xrt_profile.h>
#include <xrt/experimental/xrt_queue.h>
#include <xrt/experimental/xrt_error.h>
#include <xrt/experimental/xrt_ext.h>
#include <xrt/experimental/xrt_ini.h>
#include <xrt/experimental/xrt_message.h>
#include <xrt/experimental/xrt_system.h>
#include <xrt/experimental/xrt_aie.h>
#include <xrt/experimental/xrt_version.h>

#include <func.pb.h>

#include <common/trace_utils.h>

namespace xrt::tools::xbtracer
{
class xbreplay_msg_queue
{
public:
  xbreplay_msg_queue();
  void
  push(const std::shared_ptr<xbtracer_proto::Func>& value);

  bool
  try_pop(std::shared_ptr<xbtracer_proto::Func>& result);

  void
  wait_and_pop(std::shared_ptr<xbtracer_proto::Func>& result);

  bool
  empty();

  void
  end_queue(void);

private:
  std::queue<std::shared_ptr<xbtracer_proto::Func>> queue;
  std::mutex mlock;
  std::condition_variable cond;
  uint32_t ended;
};


void
xbreplay_receive_msgs(std::shared_ptr<xbreplay_msg_queue>& queue);


class replayer
{
public:
  int
  replay(const xbtracer_proto::Func* entry_msg, const xbtracer_proto::Func* exit_msg);

  int
  track(std::shared_ptr<xrt::device>& obj, uint64_t impl);

  // we need to explicitly delete all the tracked XRT objects, otherwise in Linux, the application
  // cleanup will crash due to "free(): invalid pointer" when it is cleaning up shared pointers during
  // application is ending.
  void
  untrack_all();

private:
  template <typename T>
  int
  track(std::shared_ptr<T>& obj, uint64_t impl, std::vector<std::tuple<uint64_t, std::shared_ptr<T>>>& tracker)
  {
    std::lock_guard<std::mutex> lock(trackers_mlock);
    for (const auto& o: tracker) {
      const auto& t_obj = std::get<1>(o);
      if (obj.get() == t_obj.get()) {
        const auto& t_impl = std::get<0>(o);
        if (impl != t_impl) {
          const std::type_info& t_type_info = typeid(T);
          xbtracer_pcritical("failed to track pointer of ", t_type_info.name(), ", ptr: ", obj.get(),
                            " already in tracker, impl: ", reinterpret_cast<void *>(impl), ", ",
                            reinterpret_cast<void*>(t_impl), ".");
        }
        else {
          return 0;
        }
      }
    }
    std::tuple<uint64_t, std::shared_ptr<T>> t(impl, obj);
    tracker.push_back(t);
    return 0;
  }

  std::mutex trackers_mlock;
  std::vector<std::tuple<uint64_t, std::shared_ptr<xrt::device>>> dev_tracker;
};

std::function<int(const xbtracer_proto::Func*, const xbtracer_proto::Func*, replayer&)>
get_func_from_signature(std::string func_s);

} // namespace xrt::tools::xbtracer

extern std::shared_ptr<xrt::tools::xbtracer::replayer> replayer_sh;

#endif // xbreplay_common_h
