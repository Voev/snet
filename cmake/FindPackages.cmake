find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if (ENABLE_UNIT_TESTS)
    find_package(GTest REQUIRED)
endif (ENABLE_UNIT_TESTS)