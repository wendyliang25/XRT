# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

# Support building XRT or its components with local build of protobuf libraries. 
SET (Protobuf_DEBUG)
INCLUDE(FindProtobuf)
if (DEFINED ENV{XRT_PROTOBUF_INSTALL})
  set(XRT_PROTOBUF_INSTALL $ENV{XRT_PROTOBUF_INSTALL})
  message("checking protobuf from ${XRT_PROTOBUF_INSTALL}.")
  set(Protobuf_INCLUDE_DIR "${XRT_PROTOBUF_INSTALL}/include")
  if (WIN32)
    set(Protobuf_LIBRARIES "${XRT_PROTOBUF_INSTALL}/lib/libprotobuf.lib")
  else (WIN32)
    set(Protobuf_LIBRARIES "${XRT_PROTOBUF_INSTALL}/lib/libprotobuf.so")
  endif(WIN32)
  find_package(Protobuf 
    HINTS ${XRT_PROTOBUF_INSTALL}
    REQUIRED)
else ()
  message("no XRT installed protobuf, checking system wide for protobuf.")
  find_package(Protobuf REQUIRED)
endif()
