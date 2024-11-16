# Set executable target name
set(EXECUTABLE_TARGET snet)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set executable target
add_executable(${EXECUTABLE_TARGET} ${SOURCES})

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
    snet_ip
    snet_tls
    snet_event
    snet_log
    snet_utils
    snet_layers
    snet_pcap
    snet_socket
    ${PCAP_LIBRARY}
    Threads::Threads
    OpenSSL::Crypto
    OpenSSL::SSL)
