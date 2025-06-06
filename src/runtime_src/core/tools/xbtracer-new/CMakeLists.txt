# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2021 Xilinx, Inc. All rights reserved.
# Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
SET (Protobuf_DEBUG)
INCLUDE(FindProtobuf)
FIND_PACKAGE(Protobuf REQUIRED)

include_directories (
${PROTOBUF_INCLUDE_DIR}
)
# Generate Cpp files from Proto file
file(GLOB PROTO_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.proto"
)

PROTOBUF_GENERATE_CPP(ProtoSources ProtoHeaders ${PROTO_SRC_FILES})

add_custom_target(xbtracer_generated_code DEPENDS ${ProtoSources} ${ProtoHeaders})
