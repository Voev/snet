# Target name
set(TARGET_NAME snet_pki_fetch)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Include dependency
include_directories(${OPENSSL_INCLUDE_DIR})

# Static library target
add_library(${TARGET_NAME} STATIC ${SOURCES})

# Dependencies

target_link_libraries(${TARGET_NAME}
    PUBLIC
        snet_crypto
        OpenSSL::SSL
)

# Code coverage target
target_code_coverage(${TARGET_NAME})
