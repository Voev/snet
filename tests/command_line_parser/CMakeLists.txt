# Set executable target name
set(EXECUTABLE_TARGET test_command_line_parser)

# Source files
aux_source_directory(${PROJECT_SOURCE_DIR}/tests/command_line_parser SOURCE_FILES)

# Set executable target
add_executable(${EXECUTABLE_TARGET} ${SOURCE_FILES})

# Link dependencies
target_link_libraries(${EXECUTABLE_TARGET}
  GTest::GTest)
