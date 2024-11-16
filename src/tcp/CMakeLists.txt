# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set target library
add_library(snet_tcp STATIC ${SOURCES})
