# Copyright 2020 M-Way Solutions GmbH
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.16.3 FATAL_ERROR)

if("${CMAKE_BINARY_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
  message(FATAL_ERROR "In-Source Build is prohibited. Please execute cmake from a different directory, e.g. the build directory. NOTE: Delete everything that was just created by CMake: CMakeFiles & CMakeCache.txt")
endif()

set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(AuthTest C)
add_executable(AuthTest)
include(cmake/add_sanitizer_flags.cmake)
target_sources(AuthTest PUBLIC "auth-plug.c")

target_compile_definitions(AuthTest PRIVATE "AUTH_TEST_ENABLED")

add_subdirectory(dep)
add_subdirectory(test)
