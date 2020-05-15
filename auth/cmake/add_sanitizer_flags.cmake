# MIT License
# 
# Copyright (c) 2016 Jakob "Brotcrunsher" Schaal
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# From: https://github.com/Brotcrunsher/BrotboxEngine

message(STATUS "My compiler is ${CMAKE_C_COMPILER_ID}")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  message(STATUS "Adding sanitizers")
  
  macro(add_sanitizer_flag flag)
    target_compile_options(AuthTest PUBLIC "-fsanitize=${flag}")
    target_link_libraries(AuthTest "-fsanitize=${flag}")
  endmacro()
  
  add_sanitizer_flag("address")
  add_sanitizer_flag("pointer-compare")
  add_sanitizer_flag("pointer-subtract")
  add_sanitizer_flag("undefined")
  add_sanitizer_flag("integer-divide-by-zero")
  add_sanitizer_flag("unreachable")
  add_sanitizer_flag("vla-bound")
  add_sanitizer_flag("null")
  add_sanitizer_flag("return")
  add_sanitizer_flag("signed-integer-overflow")
  add_sanitizer_flag("bounds-strict")
  add_sanitizer_flag("enum")
  add_sanitizer_flag("bool")
  add_sanitizer_flag("vptr")
  add_sanitizer_flag("pointer-overflow")
endif()