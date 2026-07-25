cmake_minimum_required(VERSION 3.5)

set(MX25519_VERSION 1)

project(mx25519)

set(mx25519_sources
src/portable/scalarmult.c
src/cpu.c
src/impl.c
src/mx25519.c
src/scalar.c)

if(NOT ARCH_ID)
  # allow cross compiling
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
    set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif()
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_ID)
endif()

if(NOT ARM_ID)
  set(ARM_ID "${ARCH_ID}")
endif()

if(NOT ARCH)
  set(ARCH "default")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()

message(STATUS "Build architecture: ${ARCH_ID}")

# AMD64
if(ARCH_ID STREQUAL "x86_64" OR ARCH_ID STREQUAL "x86-64" OR ARCH_ID STREQUAL "amd64")
  if(MSVC)
    enable_language(ASM_MASM)
    list(APPEND mx25519_sources src/amd64/scalarmult_masm.asm)
    set_property(SOURCE src/amd64/scalarmult_masm.asm PROPERTY LANGUAGE ASM_MASM)
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /DRELWITHDEBINFO")
  else()
    list(APPEND mx25519_sources src/amd64/scalarmult_gnu.S)
    set_property(SOURCE src/amd64/scalarmult_gnu.S PROPERTY LANGUAGE C)
    set_property(SOURCE src/amd64/scalarmult_gnu.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)
  endif()
endif()

# ARM64
if(ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  list(APPEND mx25519_sources src/arm64/scalarmult.S)
  set_property(SOURCE src/arm64/scalarmult.S PROPERTY LANGUAGE C)
  set_property(SOURCE src/arm64/scalarmult.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)
endif()

set(MX25519_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/include" CACHE STRING "mx25519 include path")

add_library(mx25519 SHARED ${mx25519_sources})
set_property(TARGET mx25519 PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET mx25519 PROPERTY PUBLIC_HEADER include/mx25519.h)
include_directories(mx25519
  include/)
target_compile_definitions(mx25519 PRIVATE MX25519_SHARED)
set_target_properties(mx25519 PROPERTIES SOVERSION ${MX25519_VERSION})

add_library(mx25519_static STATIC ${mx25519_sources})
set_property(TARGET mx25519_static PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET mx25519_static PROPERTY PUBLIC_HEADER include/mx25519.h)
include_directories(mx25519_static
  include/)
set_target_properties(mx25519_static PROPERTIES OUTPUT_NAME mx25519)
target_compile_definitions(mx25519_static PRIVATE MX25519_STATIC)

add_executable(mx25519-tests
  tests/tests.c)
include_directories(mx25519-tests
  include/
  src/)
target_compile_definitions(mx25519-tests PRIVATE MX25519_STATIC)
target_link_libraries(mx25519-tests
  PRIVATE mx25519_static)
set_property(TARGET mx25519-tests PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(mx25519-bench
  tests/bench.c
  src/cpu.c
  src/platform.c)
include_directories(mx25519-bench
  include/
  src/)
target_compile_definitions(mx25519-bench PRIVATE MX25519_STATIC)
target_link_libraries(mx25519-bench
  PRIVATE mx25519_static)
set_property(TARGET mx25519-bench PROPERTY POSITION_INDEPENDENT_CODE ON)
