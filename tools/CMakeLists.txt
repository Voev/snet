# Set executable target name
set(EXECUTABLE_TARGET snet)

# Set executable target
add_executable(${EXECUTABLE_TARGET}
    main.cpp
    perf_command.cpp
    sniffer_command.cpp)

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
  snet_lib
  ${PCAP_LIBRARY}
  Threads::Threads
  OpenSSL::Crypto
  OpenSSL::SSL)
