// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <iostream>
#include <map>
#include <string>

#include <func.pb.h>
#include <common/trace_utils.h>
#include <replay/xbreplay_common.h>

namespace xrt::tools::xbtracer
{
static std::map<std::string, std::function<int(const xbtracer_proto::Func*, const xbtracer_proto::Func*, replayer&)>> xbreplay_funcs_map = {
  {
    "xrt::device::device(unsigned int)",
    [](const xbtracer_proto::Func* entry_msg, const xbtracer_proto::Func* exit_msg, replayer& replay) {
      if (!entry_msg || !exit_msg) {
        xbtracer_pcritical("xrt::device::device(unsigned int) needs entry and exit, one of them is empty.");
      }
      if (entry_msg->arg_size() < 2) {
        xbtracer_pcritical(entry_msg->name(), " invalid number of args, ", entry_msg->arg_size(), ", ", 2, ".");
      }
      const xbtracer_proto::Arg& id_arg = entry_msg->arg(1);
      uint32_t id;
      if (id_arg.value().length() != sizeof(id)) {
        xbtracer_pcritical(entry_msg->name(), "invalid id size, ", id_arg.name(), ", size: ", id_arg.value().size(),
                           ", expected: ", sizeof(id), ".");
      }
      std::memcpy(&id, id_arg.value().data(), sizeof(id));

      uint64_t impl;
      if (exit_msg->arg_size() < 1) {
        xbtracer_pcritical(exit_msg->name(), " invalid number of exit args, ", exit_msg->arg_size(), ", ", 1, ".");
      }
      const xbtracer_proto::Arg impl_arg = exit_msg->arg(0);
      if (impl_arg.value().length() != sizeof(impl)) {
        xbtracer_pcritical(entry_msg->name(), "invalid pimpl size, ", impl_arg.name(), ", size: ", impl_arg.value().size(),
                           ", expected: ", sizeof(impl), ".");
      }
      std::memcpy(&impl, impl_arg.value().data(), sizeof(impl));

      xbtracer_pinfo("Replaying: ", entry_msg->name(), ", ", std::hex, impl, ".");
      std::shared_ptr<xrt::device> dev_sh = std::make_shared<xrt::device>(id);
      if (!dev_sh) {
        xbtracer_pcritical(entry_msg->name(), "failed to create device with id: ", id, ".");
      }
      replay.track(dev_sh, impl);
      return 0;
    }
  },
};

std::function<int(const xbtracer_proto::Func*, const xbtracer_proto::Func*, replayer&)>
get_func_from_signature(std::string func_s)
{
  auto it = xbreplay_funcs_map.find(func_s);
  if (it == xbreplay_funcs_map.end()) {
    return nullptr;
  }
  return it->second;
}

} // namespace xrt::tools::xbtracer
