# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set target library
add_library(snet_io STATIC ${SOURCES})

find_package(Boost)

include_directories(${Boost_INCLUDE_DIR})

# Building drivers
add_subdirectory(drivers)