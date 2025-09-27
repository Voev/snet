# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Target name
set(TARGET_NAME snet_pcap)

# Static library target
add_library(${TARGET_NAME} SHARED ${SOURCES})

# Find and link pcap library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Include directories
target_include_directories(
    ${TARGET_NAME}
        PRIVATE
            ${PCAP_INCLUDE_DIRS}
)

# Link dependencies
target_link_libraries(
    ${TARGET_NAME}
        PRIVATE
            snet_io
            snet_layers
            casket
            ${PCAP_LIBRARIES}
)