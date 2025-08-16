# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Target name
set(TARGET_NAME snet_nfq)

# Static library target
add_library(${TARGET_NAME} SHARED ${SOURCES})

# Find and link nfqueue library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNETFILTER_QUEUE REQUIRED libnetfilter_queue)

# Include directories
target_include_directories(
    ${TARGET_NAME}
        PRIVATE
            ${LIBNETFILTER_QUEUE_INCLUDE_DIRS}
)

# Link dependencies
target_link_libraries(
    ${TARGET_NAME}
        PRIVATE
            snet_io
            snet_layers
            snet_socket
            casket
            ${LIBNETFILTER_QUEUE_LIBRARIES}
)