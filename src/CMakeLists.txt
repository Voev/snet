# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set target library
add_library(snet_lib STATIC ${SOURCES})
