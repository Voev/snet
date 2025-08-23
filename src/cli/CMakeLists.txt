# Set executable target name
set(EXECUTABLE_TARGET snet)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set executable target
add_executable(${EXECUTABLE_TARGET} ${SOURCES})

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
    casket
    snet_crypto
    snet_tls
    snet_event
    snet_layers
    snet_io
    snet_socket
    ${PCAP_LIBRARY}
    Threads::Threads
    OpenSSL::Crypto
    OpenSSL::SSL)
