# Sources
file(GLOB_RECURSE SOURCES *.c)

# Set target library
add_library(snet_api STATIC ${SOURCES})
