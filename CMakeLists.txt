cmake_minimum_required(VERSION 3.20)
project(cwe-scan CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Builds against an installed LLVM/Clang 20 (Ubuntu's llvm-20-dev and
# libclang-20-dev), found through llvm-config. LLVM_ROOT points at an
# unpacked copy when the packages aren't installed system-wide.
find_program(LLVM_CONFIG NAMES llvm-config-20 llvm-config
             HINTS ${LLVM_ROOT}/bin /usr/lib/llvm-20/bin REQUIRED)
foreach(q includedir libdir version)
  execute_process(COMMAND ${LLVM_CONFIG} --${q} OUTPUT_VARIABLE LLVM_${q}
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
endforeach()
string(REGEX MATCH "^[0-9]+" LLVM_MAJOR "${LLVM_version}")
message(STATUS "LLVM ${LLVM_version} at ${LLVM_libdir}")

add_executable(cwe-scan src/main.cpp src/analysis.cpp src/facts.cpp)
target_include_directories(cwe-scan SYSTEM PRIVATE ${LLVM_includedir})
target_link_directories(cwe-scan PRIVATE ${LLVM_libdir})
target_link_libraries(cwe-scan PRIVATE clang-cpp LLVM)
target_compile_options(cwe-scan PRIVATE -Wall -Wextra -fno-exceptions)
target_compile_definitions(cwe-scan PRIVATE
  CWE_SCAN_RESOURCE_DIR="${LLVM_libdir}/clang/${LLVM_MAJOR}")
set_target_properties(cwe-scan PROPERTIES BUILD_RPATH ${LLVM_libdir})
