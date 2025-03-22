# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_library(snet_nfq SHARED ${SOURCES})

# Find and link pcap library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNETFILTER_QUEUE REQUIRED libnetfilter_queue)
pkg_check_modules(LIBMNL REQUIRED libmnl)

target_link_libraries(snet_nfq PRIVATE ${LIBNETFILTER_QUEUE_INCLUDE_DIRS} ${LIBMNL_INCLUDE_DIRS} )
target_link_libraries(snet_nfq snet_io ${LIBMNL_LIBRARIES} ${LIBNETFILTER_QUEUE_LIBRARIES})