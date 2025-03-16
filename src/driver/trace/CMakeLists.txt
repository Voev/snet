# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_library(snet_trace SHARED ${SOURCES})
