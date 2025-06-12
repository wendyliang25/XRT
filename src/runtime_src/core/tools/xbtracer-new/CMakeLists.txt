# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

include (${XRT_SOURCE_DIR}/CMake/protobufUtil.cmake)

include_directories (
${PROTOBUF_INCLUDE_DIR}
${CMAKE_CURRENT_BINARY_DIR}
)
# Generate Cpp files from Proto file
file(GLOB PROTO_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.proto"
)

PROTOBUF_GENERATE_CPP(ProtoSources ProtoHeaders ${PROTO_SRC_FILES})

add_custom_target(xbtracer_generated_code DEPENDS ${ProtoSources} ${ProtoHeaders})

add_library(xbtracer_protobuf STATIC ${ProtoSources} ${ProtoHeaders})
add_dependencies(xbtracer_protobuf xbtracer_generated_code)
if (MSVC)
  target_compile_options(xbtracer_protobuf PRIVATE /wd4244 /wd4267)
endif(MSVC)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")

file(GLOB XBTRACER_COMMON_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/common/*.cpp"
)

add_library(xbtracer_common STATIC ${XBTRACER_COMMON_SRC_FILES})

file(GLOB XBTRACER_WRAPPER_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/wrapper/*.cpp"
)

add_library(xrt_wrapper SHARED ${XBTRACER_WRAPPER_SRC_FILES} ${ProtoHeaders})

target_link_libraries(xrt_wrapper PRIVATE xbtracer_common xbtracer_protobuf ${Protobuf_LIBRARIES})
add_dependencies(xrt_wrapper xbtracer_common xbtracer_protobuf)

file(GLOB XBTRACER_CAPTURE_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/capture/*.cpp"
)

add_executable(xbtracer ${XBTRACER_CAPTURE_SRC_FILES})

target_link_libraries(xbtracer PRIVATE xbtracer_common)
add_dependencies(xbtracer xbtracer_common)

if (WIN32)
include (detoursUtil.cmake)

target_include_directories(xrt_wrapper PRIVATE ${DETOURS_INCLUDE})
target_link_libraries(xrt_wrapper PRIVATE ms_detours)
add_dependencies(xrt_wrapper ms_detours)
target_include_directories(xbtracer PRIVATE ${DETOURS_INCLUDE})
target_link_libraries(xbtracer PRIVATE ms_detours)
add_dependencies(xbtracer ms_detours)
endif(WIN32)

