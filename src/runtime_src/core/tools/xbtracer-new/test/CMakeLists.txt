# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

set (TEST_XRT_LIB_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_lib.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_lib.h
)
add_library(test_xrt_lib SHARED ${TEST_XRT_LIB_SRC_FILES})
target_link_libraries(test_xrt_lib PRIVATE xrt_coreutil)
add_dependencies(test_xrt_lib xrt_coreutil)

set (TEST_XRT_FLOW_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_lib.h
)
add_executable(test_xrt_flow ${TEST_XRT_FLOW_SRC_FILES})
target_link_libraries(test_xrt_flow PRIVATE test_xrt_lib)
add_dependencies(test_xrt_flow test_xrt_lib)

set (TEST_XRT_FLOW_DYNAMIC_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_dynamic.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_lib.h
)
add_executable(test_xrt_flow_dynamic ${TEST_XRT_FLOW_DYNAMIC_SRC_FILES})
target_link_libraries(test_xrt_flow_dynamic)

set (TEST_XRT_FLOW_CRASH_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_crash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xrt_flow_lib.h
)
add_executable(test_xrt_flow_crash ${TEST_XRT_FLOW_CRASH_SRC_FILES})
target_link_libraries(test_xrt_flow_crash PRIVATE test_xrt_lib)
add_dependencies(test_xrt_flow_crash test_xrt_lib)
