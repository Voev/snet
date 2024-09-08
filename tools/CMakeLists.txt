# Set executable target name
set(EXECUTABLE_TARGET snet)

# Source files
# aux_source_directory(${PROJECT_SOURCE_DIR}/tools SOURCE_FILES)

# Set executable target
add_executable(${EXECUTABLE_TARGET} main.cpp)

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
  snet_lib
  OpenSSL::Crypto
  OpenSSL::SSL)
