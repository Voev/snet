cmake_minimum_required(VERSION 3.10)
file(STRINGS "version.txt" VERSION_STRING)

project(snet
        LANGUAGES CXX
        VERSION ${VERSION_STRING})

# Set path to CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Custom options
option (ENABLE_UNIT_TESTS "Enable unit tests" ON)
option (ENABLE_CODE_COVERAGE "Enable code coverage" OFF)

# Include CMake modules
include(ConfigureCompiler)
include(FindPackages)

# Configure result directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include project directory
include_directories(${PROJECT_SOURCE_DIR}/include)

# Entry point for sources
add_subdirectory(src)
add_subdirectory(tools)

# Test options
if (ENABLE_UNIT_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif (ENABLE_UNIT_TESTS)

# Coverage options
if (ENABLE_CODE_COVERAGE)
  setup_target_for_coverage_lcov(
    NAME coverage
    EXECUTABLE ctest -V ${CTEST_VERBOSE_FLAG}
    EXCLUDE "${PROJECT_SOURCE_DIR}/tests/*"
    LCOV_ARGS "--no-external")
endif (ENABLE_CODE_COVERAGE)
