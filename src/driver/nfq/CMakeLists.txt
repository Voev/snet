# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_library(snet_nfq SHARED ${SOURCES})

# Find and link pcap library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNETFILTER_QUEUE REQUIRED libnetfilter_queue)

target_link_libraries(snet_nfq PRIVATE ${LIBNETFILTER_QUEUE_INCLUDE_DIRS})
target_link_libraries(snet_nfq snet_io snet_socket ${LIBNETFILTER_QUEUE_LIBRARIES})