# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Target name
set(TARGET_NAME snet_afpacket)

# Static library target
add_library(${TARGET_NAME} SHARED ${SOURCES})

# Find and link pcap library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Link dependencies
target_link_libraries(
    ${TARGET_NAME}
        PRIVATE
            snet_io
            snet_layers
            casket
            ${PCAP_LIBRARIES}
)