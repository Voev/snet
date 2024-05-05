#add_subdirectory(client)
#add_subdirectory(server)
#add_subdirectory(perf)

# Set executable target name
set(EXECUTABLE_TARGET snet)

# Source files
aux_source_directory(${PROJECT_SOURCE_DIR}/src SOURCE_FILES)

# Set executable target
add_executable(${EXECUTABLE_TARGET} ${SOURCE_FILES})

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
  OpenSSL::Crypto
  OpenSSL::SSL
  Threads::Threads)
