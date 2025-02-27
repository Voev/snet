# Sources
file(GLOB_RECURSE SOURCES *.c)

# Static library target
add_library(daq_pcap SHARED ${SOURCES})

# Find and link pcap library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
target_link_libraries(daq_pcap ${PCAP_LIBRARIES})