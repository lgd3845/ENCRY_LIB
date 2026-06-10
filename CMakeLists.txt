cmake_minimum_required(VERSION 3.20)

project(encrylib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_library(encrylib_core
  src/crypto.cpp
  src/hmac_sm3.cpp
  src/secure_bytes.cpp
  src/sm3.cpp
  src/sm4.cpp
  src/util.cpp
  src/vault.cpp
)

target_include_directories(encrylib_core PUBLIC include)
target_link_libraries(encrylib_core PUBLIC Threads::Threads)

target_compile_options(encrylib_core PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion -O3>
)

add_executable(encrylib src/main.cpp)
target_link_libraries(encrylib PRIVATE encrylib_core)

add_executable(encrylib_tests tests/test_crypto.cpp)
target_link_libraries(encrylib_tests PRIVATE encrylib_core)

add_executable(encrylib_bench benchmarks/bench_crypto.cpp)
target_link_libraries(encrylib_bench PRIVATE encrylib_core)

enable_testing()
add_test(NAME crypto_tests COMMAND encrylib_tests)
