# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Include dependency
include_directories(${OPENSSL_INCLUDE_DIR})

# Static library target
add_library(snet_crypto STATIC ${SOURCES})

# Dependencies
target_link_libraries(snet_crypto PUBLIC OpenSSL::Crypto)

# Code coverage target
target_code_coverage(snet_crypto)
