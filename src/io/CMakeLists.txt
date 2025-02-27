# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set target library
add_library(snet_io STATIC ${SOURCES})

# Building drivers
add_subdirectory(drivers)