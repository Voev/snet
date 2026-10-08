# Target name
set(TARGET_NAME snet_tcp_proxy)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_executable(${TARGET_NAME} ${SOURCES})

# Dependencies
target_link_libraries(${TARGET_NAME}
    PUBLIC
        snet_io
        snet_layers
        snet_tls
        snet_proxy
        casket
        Threads::Threads
)
