# Application name
set(TEST_NAME snet_tls_test)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Set executable target
add_executable(${TEST_NAME} ${SOURCES})

# Set dependencies
target_link_libraries(${TEST_NAME}
    PRIVATE
        snet_tls
        snet_tls_ex
        snet_crypto
        OpenSSL::Crypto
        OpenSSL::SSL
        GTest::GTest)

option(SNET_TLS_TEST_KEYS_FROM_FILE "Load test keys from files via env vars" OFF)
if(SNET_TLS_TEST_KEYS_FROM_FILE)
    target_compile_definitions(${TEST_NAME} PRIVATE SNET_TLS_TEST_KEYS_FROM_FILE)
endif()

# Discover tests
gtest_discover_tests(
    ${TEST_NAME}
    XML_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_NAME}.reports
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# Code coverage
target_code_coverage(${TEST_NAME} AUTO PRIVATE)
