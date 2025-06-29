cmake_minimum_required(VERSION 3.10)
file(STRINGS "version.txt" VERSION_STRING)

project(snet
        LANGUAGES C CXX
        VERSION ${VERSION_STRING})

# C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set path to CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Custom options
option (ENABLE_UNIT_TESTS "Enable unit tests" OFF)
option (ENABLE_CODE_COVERAGE "Enable code coverage" OFF)

# Include CMake modules
include(ConfigureCompiler)
include(FindPackages)
include(Sanitizers)
include(CodeCoverage)

# Set submodules path
set(SUBMODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/modules")
add_subdirectory(${SUBMODULE_PATH}/casket)
include_directories(${SUBMODULE_PATH}/casket/include)

# Configure result directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include project directory
include_directories(${PROJECT_SOURCE_DIR}/include)

# Code coverage
if (ENABLE_CODE_COVERAGE)
  add_code_coverage()
endif (ENABLE_CODE_COVERAGE)

# Entry point for sources
add_subdirectory(src)

# Test options
if (ENABLE_UNIT_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif (ENABLE_UNIT_TESTS)

