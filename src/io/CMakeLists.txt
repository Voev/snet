# Sources
file(GLOB_RECURSE SOURCES *.cpp)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set target library
add_library(snet_io STATIC ${SOURCES})
