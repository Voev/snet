# Target name
set(TARGET_NAME snet_pki_manager)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Include dependency
include_directories(${OPENSSL_INCLUDE_DIR})

# Static library target
add_executable(${TARGET_NAME} ${SOURCES})

# Dependencies
target_link_libraries(${TARGET_NAME} PUBLIC snet_cert_cache)
