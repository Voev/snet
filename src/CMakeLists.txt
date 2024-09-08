# Library name
set(LIB_NAME snet)

# Sources
file(GLOB_RECURSE SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" *.cpp)

# Set target library
add_library(${LIB_NAME} STATIC ${SOURCES})
