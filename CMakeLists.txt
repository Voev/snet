cmake_minimum_required(VERSION 3.10)
project(snet LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(${PROJECT_SOURCE_DIR}/include)
include(CompilerSettings)
include(OpenSSLSettings)
add_subdirectory(async_client)
add_subdirectory(server)
