# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Include dependency
include_directories(${OPENSSL_INCLUDE_DIR})

# Static library target
add_library(snet_crypto STATIC ${SOURCES})

# Code coverage target
target_code_coverage(snet_crypto)
