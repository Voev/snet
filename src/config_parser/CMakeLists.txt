# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_library(snet_config_parser STATIC ${SOURCES})

# Code coverage target
target_code_coverage(snet_config_parser)
