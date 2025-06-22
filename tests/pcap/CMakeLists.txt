# Application name
set(TEST_NAME snet_pcap_test)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set executable target
add_executable(${TEST_NAME} ${SOURCES})

# Set dependencies
target_link_libraries(${TEST_NAME}
    PRIVATE
        snet_tls
        snet_layers
        snet_io
        GTest::GTest)

# Set custom target for PCAP tests
add_custom_target(run_pcap_tests
    COMMAND ${TEST_NAME} --config ${PROJECT_SOURCE_DIR}/tests/pcap/data/tests.conf --driver ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsnet_pcap.so
    DEPENDS ${TEST_NAME}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Running PCAP tests..."
)

# Code coverage
target_code_coverage(${TEST_NAME} AUTO PRIVATE)
