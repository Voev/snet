# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set include directory for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Set target library
add_library(snet_tls STATIC ${SOURCES})
