# Target name
set(TARGET_NAME driver_test)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Include dependency
include_directories(${OPENSSL_INCLUDE_DIR})

# Static library target
add_executable(${TARGET_NAME} ${SOURCES})

# Dependencies
target_link_libraries(${TARGET_NAME}
    PUBLIC
        snet_io
        snet_layers
        casket
        Threads::Threads)
