# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_library(snet_ip STATIC ${SOURCES})

# Code coverage target
target_code_coverage(snet_ip)